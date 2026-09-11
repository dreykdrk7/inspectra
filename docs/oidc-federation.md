# Federación OIDC privada

Estado: vertical inicial de `PROD-039`, implementado y validado con un proveedor
simulado. No se ha validado contra un IdP real ni convierte Inspectra en servicio
SaaS o despliegue público.

## Alcance soportado

La federación es un complemento opt-in de
`INSPECTRA_AUTH_MODE=private_team_lightweight_users`. El administrador local
bootstrap continúa siendo la vía de ruptura. Inspectra usa Authorization Code,
PKCE `S256`, `state` de un solo uso ligado a una cookie `HttpOnly` y `nonce`.
Valida criptográficamente el ID token con `RS256` o `ES256`, `kid` único,
`iss`, `aud`, `azp` cuando corresponde, `exp`, `iat`, `sub` y `nonce`.

El flujo deliberadamente no hace JIT provisioning. Antes del primer login, un
administrador crea o invita a un miembro local `reader` o `maintainer` y liga
su `sub` mediante la superficie administrativa. SQLite solo conserva un
HMAC-SHA-256 de `issuer + sub`; ni `sub`, grupos, tokens, códigos, verifier,
client secret ni claves externas se escriben en almacenamiento. Un miembro
`administrator` nunca puede federarse en este corte.

El ID token debe contener una lista `groups` con exactamente uno de los dos
grupos configurados. El rol afirmado debe coincidir con la membresía local:
ninguno de los dos lados puede elevar al otro. La organización es fija y
procede de configuración del operador, nunca del navegador ni del token. Puede
exigirse además un claim de tenant con valor exacto.

## Configuración completa y segura

La federación está deshabilitada cuando todas estas variables están ausentes.
Una configuración parcial impide arrancar. Los endpoints son URLs HTTPS fijas,
sin credenciales, query ni fragmento, y deben compartir el origen exacto del
issuer. El callback solo admite `/auth/oidc/callback`; HTTP solo se tolera para
callbacks localhost de desarrollo.

```text
INSPECTRA_OIDC_ISSUER=https://id.example.test/tenant
INSPECTRA_OIDC_AUTHORIZATION_ENDPOINT=https://id.example.test/tenant/authorize
INSPECTRA_OIDC_TOKEN_ENDPOINT=https://id.example.test/tenant/token
INSPECTRA_OIDC_JWKS_URI=https://id.example.test/tenant/jwks
INSPECTRA_OIDC_CLIENT_ID=inspectra-private
INSPECTRA_OIDC_CLIENT_SECRET=<secret-del-operador>
INSPECTRA_OIDC_REDIRECT_URI=https://inspectra.example.test/auth/oidc/callback
INSPECTRA_OIDC_POST_LOGIN_REDIRECT_URI=https://inspectra.example.test/
INSPECTRA_OIDC_ORGANIZATION_ID=local-admin
INSPECTRA_OIDC_READER_GROUP=inspectra-readers
INSPECTRA_OIDC_MAINTAINER_GROUP=inspectra-maintainers
INSPECTRA_OIDC_SUBJECT_HMAC_KEY=<32-bytes-base64url-sin-padding>
INSPECTRA_OIDC_TENANT_CLAIM=tid
INSPECTRA_OIDC_EXPECTED_TENANT=<tenant-exacto>
```

Las dos últimas variables son opcionales, pero se definen juntas. El HMAC se
puede generar fuera del historial y de logs con un generador criptográfico de
32 bytes y codificación base64url sin `=`. Debe entregarse mediante el gestor
de secretos del despliegue, no mediante un archivo versionado.

Registre exactamente el callback en el IdP y haga que este emita `groups` en el
ID token. Después, el administrador acepta/invita la cuenta local y usa
`POST /organization/federated-identities` con el `user_id` del miembro y el
`sub` exacto. La respuesta no devuelve el `sub`. La revocación usa
`DELETE /organization/federated-identities/{binding_id}` e invalida las
sesiones de ese miembro en la organización.

## Egress y amenazas cubiertas

- No existe discovery ni URL aportada por usuario: issuer, autorización, token
  y JWKS proceden solo del entorno y el host debe ser el mismo.
- Las llamadas de token/JWKS usan HTTPS, `trust_env=false`, cero redirecciones,
  timeout de 5 s, respuestas de hasta 256 KiB y concurrencia máxima cuatro.
- Solo salen código/verifier/redirect/client authentication hacia el endpoint
  fijo del IdP. No se envían proyecto, archivos, rutas, hallazgos ni datos de
  análisis.
- `state`, nonce, verifier y binding viven en memoria como máximo cinco minutos,
  están acotados a 256 transacciones y se consumen una sola vez. Un reinicio
  cancela de forma segura los logins iniciados.
- El inicio anónimo tiene un límite separado de diez transacciones por cliente
  y ventana de cinco minutos, con `429` y `Retry-After`; no debilita ni comparte
  contadores con el login por contraseña.
- El JWKS normalizado se conserva en memoria una hora; no se persiste la
  respuesta del proveedor. El ID token y access token no se conservan.
- Errores del IdP, token inválido, tenant/grupo inesperado, cuenta no
  provisionada o rol discordante producen el mismo resultado público. La
  telemetría registra solo un código cerrado, nunca claims ni contenido externo.

Este diseño sigue las validaciones de [OpenID Connect Core
1.0](https://openid.net/specs/openid-connect-core-1_0-18.html) y las defensas de
PKCE, mix-up, CSRF y redirect de [OAuth 2.0 Security Best Current Practice (RFC
9700)](https://www.rfc-editor.org/rfc/rfc9700.html). La lista de algoritmos se
fija en configuración de código y no se deriva del token, conforme a la
[advertencia de la API de PyJWT](https://pyjwt.readthedocs.io/en/stable/api.html).

## Rotación y operación

Para rotar el client secret: cree primero el nuevo secreto en el IdP, actualice
el secreto externo de Inspectra, reinicie de forma controlada y confirme un
login nuevo antes de retirar el anterior. Inspectra no persiste el secreto. La
rotación de `INSPECTRA_OIDC_SUBJECT_HMAC_KEY` cambia todos los digests: requiere
revocar y volver a provisionar las ligaduras en una ventana planificada; no
deben configurarse dos claves implícitas ni degradarse a SHA sin clave.

La baja inmediata se ejecuta en Inspectra revocando binding o membresía. Un
cambio en el IdP por sí solo se refleja al siguiente login; una sesión ya
emitida vive hasta su TTL local. Back-channel logout, SCIM, refresh tokens,
introspección y descubrimiento multiissuer no están implementados. Para
incidentes, revoque además la membresía local y sus sesiones.

## Validación y límites

La suite ordinaria usa claves efímeras y un IdP simulado; no necesita Internet.
Incluye token/audience/issuer/nonce inválidos, tenant cruzado, grupo desconocido
o ambiguo, provider caído, redirección, exceso de tamaño, rol administrador,
aprovisionamiento, login, aislamiento y revocación de sesión. Antes de adoptar
un proveedor real hace falta un ensayo autorizado con su configuración exacta,
rotación JWKS y comportamiento de claims. Hasta entonces el estado correcto es
**implementado y validado con fixtures, no validado contra proveedor real**.
