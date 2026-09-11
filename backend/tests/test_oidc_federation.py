import asyncio
from datetime import datetime, timedelta, timezone

import jwt
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth import hash_password
from app.oidc_federation import (
    OidcFederationConfig,
    OidcFederationError,
    OidcProviderClient,
    OidcTransactionStore,
    authenticate_oidc_callback,
)
from app.team_identity import TeamIdentityError, TeamIdentityStore


ISSUER = "https://id.example.test/tenant-a"
CLIENT_ID = "inspectra-private"
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def oidc_config(**changes) -> OidcFederationConfig:
    values = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "client_id": CLIENT_ID,
        "client_secret": "client-secret-kept-outside-storage",
        "redirect_uri": "https://inspectra.example.test/auth/oidc/callback",
        "post_login_redirect_uri": "https://inspectra.example.test/",
        "organization_id": "local-admin",
        "reader_group": "inspectra-readers",
        "maintainer_group": "inspectra-maintainers",
        "subject_hmac_key": b"k" * 32,
        "tenant_claim": "tid",
        "expected_tenant": "tenant-a",
    }
    values.update(changes)
    return OidcFederationConfig(**values)


def signed_token(private_key, transaction, **changes) -> str:
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "provider-subject-123",
        "nonce": transaction.nonce,
        "iat": NOW,
        "exp": NOW + timedelta(minutes=5),
        "groups": ["inspectra-readers"],
        "tid": "tenant-a",
    }
    claims.update(changes)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})


def public_jwks(private_key) -> dict[str, object]:
    public_key = private_key.public_key()
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk.update({"kid": "test-key", "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def test_oidc_config_rejects_cross_origin_provider_and_non_https_redirects():
    with pytest.raises(ValueError, match="share the configured issuer origin"):
        oidc_config(jwks_uri="https://attacker.example/jwks")
    with pytest.raises(ValueError, match="redirect URI"):
        oidc_config(redirect_uri="http://inspectra.example.test/auth/oidc/callback")


def test_oidc_transaction_is_browser_bound_single_use_and_pkce_is_present():
    store = OidcTransactionStore()
    transaction = store.create()
    authorization_url = oidc_config().authorization_url(transaction)
    assert "code_challenge_method=S256" in authorization_url
    assert "scope=openid" in authorization_url
    with pytest.raises(OidcFederationError, match="invalid_browser_binding"):
        store.consume(transaction.state, "wrong-binding")
    with pytest.raises(OidcFederationError, match="invalid_state"):
        store.consume(transaction.state, transaction.binding)


def test_oidc_provider_does_not_follow_redirects_or_accept_oversized_responses():
    redirected = OidcProviderClient(
        oidc_config(),
        transport=httpx.MockTransport(lambda _request: httpx.Response(302, headers={"location": "https://attacker.example/token"})),
    )
    with pytest.raises(OidcFederationError) as redirect_error:
        asyncio.run(redirected.exchange_code("code", "verifier"))
    assert redirect_error.value.code == "provider_unavailable"

    oversized = OidcProviderClient(
        oidc_config(),
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, content=b"x" * 262_145)
        ),
    )
    with pytest.raises(OidcFederationError) as size_error:
        asyncio.run(oversized.exchange_code("code", "verifier"))
    assert size_error.value.code == "provider_response_too_large"


def test_oidc_provider_failure_is_controlled_without_token_fallback():
    transaction = OidcTransactionStore().create()

    async def unavailable(_code, _verifier):
        raise OidcFederationError("provider_unavailable")

    async def must_not_load_keys():
        raise AssertionError("JWKS must not be loaded after a failed token exchange")

    with pytest.raises(OidcFederationError) as caught:
        asyncio.run(
            authenticate_oidc_callback(
                config=oidc_config(),
                transaction=transaction,
                code="authorization-code",
                exchange_code=unavailable,
                load_jwks=must_not_load_keys,
            )
        )
    assert caught.value.code == "provider_unavailable"


def test_oidc_validates_signature_claims_tenant_and_exact_group():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transaction = OidcTransactionStore().create()

    async def exchange(_code, verifier):
        assert verifier == transaction.code_verifier
        return signed_token(private_key, transaction)

    async def jwks():
        return public_jwks(private_key)

    identity = asyncio.run(
        authenticate_oidc_callback(
            config=oidc_config(),
            transaction=transaction,
            code="authorization-code",
            exchange_code=exchange,
            load_jwks=jwks,
        )
    )
    assert identity.asserted_role == "reader"
    assert identity.subject_digest == oidc_config().subject_digest("provider-subject-123")


@pytest.mark.parametrize(
    ("claim_changes", "expected_code"),
    [
        ({"aud": "another-client"}, "invalid_id_token"),
        ({"iss": "https://id.example.test/tenant-b"}, "invalid_id_token"),
        ({"nonce": "replayed-nonce"}, "invalid_nonce"),
        ({"tid": "tenant-b"}, "unexpected_tenant"),
        ({"groups": ["unrelated-group"]}, "unexpected_group"),
        ({"groups": ["inspectra-readers", "inspectra-maintainers"]}, "unexpected_group"),
    ],
)
def test_oidc_rejects_invalid_tokens_cross_tenant_and_ambiguous_groups(claim_changes, expected_code):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transaction = OidcTransactionStore().create()

    async def exchange(_code, _verifier):
        return signed_token(private_key, transaction, **claim_changes)

    async def jwks():
        return public_jwks(private_key)

    with pytest.raises(OidcFederationError) as caught:
        asyncio.run(
            authenticate_oidc_callback(
                config=oidc_config(),
                transaction=transaction,
                code="authorization-code",
                exchange_code=exchange,
                load_jwks=jwks,
            )
        )
    assert caught.value.code == expected_code


def test_federated_binding_is_preprovisioned_scoped_and_revocable(tmp_path):
    store = TeamIdentityStore(
        tmp_path / "identity.sqlite3",
        organization_name="Test team",
        bootstrap_admin_password_hash=hash_password("bootstrap-password"),
        invitation_ttl_seconds=600,
    )
    admin = store.authenticate("admin", "bootstrap-password")
    assert admin is not None
    invitation = store.create_invitation(principal=admin, username="reader.one", role="reader")
    member = store.accept_invitation(token=invitation.token, password="reader-password-long")
    digest = oidc_config().subject_digest("provider-subject-123")

    binding = store.provision_federated_identity(
        principal=admin,
        user_id=member.user_id,
        subject_digest=digest,
    )
    resolved = store.resolve_federated_principal(
        organization_id=admin.organization_id,
        subject_digest=digest,
        asserted_role="reader",
    )
    assert resolved is not None and resolved.user_id == member.user_id
    assert store.resolve_federated_principal(
        organization_id=admin.organization_id,
        subject_digest=digest,
        asserted_role="maintainer",
    ) is None

    revoked = store.revoke_federated_identity(principal=admin, binding_id=binding.binding_id)
    assert revoked.revoked_at is not None
    assert store.resolve_federated_principal(
        organization_id=admin.organization_id,
        subject_digest=digest,
        asserted_role="reader",
    ) is None


def test_federated_identity_never_provisions_an_administrator(tmp_path):
    store = TeamIdentityStore(
        tmp_path / "identity.sqlite3",
        organization_name="Test team",
        bootstrap_admin_password_hash=hash_password("bootstrap-password"),
        invitation_ttl_seconds=600,
    )
    admin = store.authenticate("admin", "bootstrap-password")
    assert admin is not None
    with pytest.raises(TeamIdentityError) as caught:
        store.provision_federated_identity(
            principal=admin,
            user_id=admin.user_id,
            subject_digest="a" * 64,
        )
    assert caught.value.code == "federated_administrator_forbidden"
