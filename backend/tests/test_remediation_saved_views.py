from datetime import datetime, timezone
import json

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.remediation_saved_views import (
    MAX_SAVED_VIEWS_PER_USER,
    RemediationSavedViewCreateRequest,
    RemediationSavedViewError,
    RemediationSavedViewFilters,
    RemediationSavedViewStore,
)


NOW = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
OWNER_A = "a" * 32
OWNER_B = "b" * 32
USER_A = "1" * 32
USER_B = "2" * 32


def settings(tmp_path):
    value = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    value.ensure_directories()
    return value


def payload(name="Urgent npm", *, visibility="private", make_default=False):
    return RemediationSavedViewCreateRequest(
        name=name,
        visibility=visibility,
        make_default=make_default,
        filters=RemediationSavedViewFilters(
            priority="urgent", ecosystem="npm", workflow_state="open", sort="projects"
        ),
    )


def test_private_shared_default_and_delete_are_user_and_owner_scoped(tmp_path):
    ids = iter([f"{value:032x}" for value in range(1, 8)])
    store = RemediationSavedViewStore(settings(tmp_path), now_func=lambda: NOW, id_factory=ids.__next__)
    private = store.create(OWNER_A, USER_A, payload(make_default=True), can_share=False)
    shared = store.create(
        OWNER_A, USER_A, payload("Team high risk", visibility="organization"), can_share=True
    )
    other_private = store.create(OWNER_A, USER_B, payload("My review queue"), can_share=False)
    foreign = store.create(OWNER_B, USER_B, payload("Foreign queue"), can_share=False)

    user_a = store.list_visible(OWNER_A, USER_A)
    assert {item.id for item in user_a.items} == {private.id, shared.id}
    assert user_a.default_view_id == private.id
    user_b = store.list_visible(OWNER_A, USER_B)
    assert {item.id for item in user_b.items} == {shared.id, other_private.id}
    assert foreign.id not in {item.id for item in user_b.items}

    selected = store.set_default(OWNER_A, USER_B, shared.id)
    assert selected.default_view_id == shared.id
    with pytest.raises(RemediationSavedViewError, match="view_not_found"):
        store.set_default(OWNER_A, USER_A, other_private.id)
    with pytest.raises(RemediationSavedViewError, match="view_not_found"):
        store.delete(OWNER_A, USER_B, private.id)

    assert store.delete(OWNER_A, USER_A, shared.id) == shared
    assert store.list_visible(OWNER_A, USER_B).default_view_id is None
    restarted = RemediationSavedViewStore(store.settings)
    assert [item.id for item in restarted.list_visible(OWNER_A, USER_A).items] == [private.id]


def test_share_requires_privileged_role_and_contract_rejects_sensitive_free_text(tmp_path):
    store = RemediationSavedViewStore(settings(tmp_path), id_factory=lambda: "1" * 32)
    with pytest.raises(RemediationSavedViewError, match="share_forbidden"):
        store.create(OWNER_A, USER_A, payload(visibility="organization"), can_share=False)
    with pytest.raises(ValidationError):
        RemediationSavedViewCreateRequest.model_validate({
            "name": "Unsafe path /srv/customer",
            "visibility": "private",
            "filters": {"search": "private-project", "cursor": "secret-cursor"},
        })


def test_limit_duplicate_name_and_corruption_fail_closed(tmp_path):
    ids = iter([f"{value:032x}" for value in range(1, MAX_SAVED_VIEWS_PER_USER + 2)])
    store = RemediationSavedViewStore(settings(tmp_path), id_factory=ids.__next__)
    store.create(OWNER_A, USER_A, payload(), can_share=False)
    assert (store.directory / f"{OWNER_A}.json").stat().st_mode & 0o077 == 0
    with pytest.raises(RemediationSavedViewError, match="name_conflict"):
        store.create(OWNER_A, USER_A, payload("urgent NPM"), can_share=False)
    for value in range(1, MAX_SAVED_VIEWS_PER_USER):
        store.create(OWNER_A, USER_A, payload(f"Queue {value:02d}"), can_share=False)
    with pytest.raises(RemediationSavedViewError, match="view_limit"):
        store.create(OWNER_A, USER_A, payload("One too many"), can_share=False)

    path = store.directory / f"{OWNER_A}.json"
    persisted = json.loads(path.read_text(encoding="utf-8"))
    persisted["views"][0]["organization_id"] = OWNER_B
    path.write_text(json.dumps(persisted), encoding="utf-8")
    with pytest.raises(RemediationSavedViewError, match="store_invalid"):
        store.list_visible(OWNER_A, USER_A)


def test_member_cleanup_removes_owned_views_and_defaults_without_touching_others(tmp_path):
    ids = iter([f"{value:032x}" for value in range(1, 5)])
    store = RemediationSavedViewStore(settings(tmp_path), id_factory=ids.__next__)
    removed = store.create(OWNER_A, USER_A, payload(make_default=True), can_share=False)
    retained = store.create(OWNER_A, USER_B, payload("Retained queue", make_default=True), can_share=False)
    assert store.delete_user(OWNER_A, USER_A) == 1
    assert removed.id not in {item.id for item in store.list_visible(OWNER_A, USER_B).items}
    assert store.list_visible(OWNER_A, USER_B).default_view_id == retained.id
