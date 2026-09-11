# Eventos firmados para integraciones

Estado: primer vertical de `PROD-071`. Está implementado para estados terminales
de análisis de proyecto y validado únicamente con receptores simulados. No hay
destino configurado ni tráfico saliente por defecto.

## Contrato y datos enviados

El contrato `2026-09-11.1` emite un `POST` JSON solo cuando un análisis de
proyecto queda `completed`, `failed` o `cancelled`. El cuerpo está limitado a
8 KiB y contiene exactamente:

- versión y tipo fijo `analysis.terminal`;
- ID de evento SHA-256 determinista para deduplicación;
- instante UTC de terminación;
- IDs opacos de proyecto y análisis;
- estado terminal y, si el resultado lo ofrece de forma estructurada, número
  agregado de hallazgos.

No contiene organización, nombre de proyecto, usuario, archivo, ruta, código,
hash de fuente, componente, vulnerabilidad, evidencia, error, target, URL,
credencial ni respuesta del proveedor. El outbox SQLite conserva ese mismo
payload mínimo y estado operativo; nunca conserva endpoint ni clave de firma.

## Configuración opt-in

Las cuatro variables sensibles/identificadoras son todo-o-nada y solo se
aceptan si el interruptor está habilitado. El endpoint debe ser una URL HTTPS
fija en puerto 443, sin usuario, contraseña, query, fragmento ni segmentos de
ruta ambiguos. Su hostname canónico debe coincidir exactamente con la allowlist
de un solo host fijada por el operador.

```text
INSPECTRA_INTEGRATION_EVENTS_ENABLED=true
INSPECTRA_INTEGRATION_EVENT_ENDPOINT=https://hooks.example.test/inspectra/events
INSPECTRA_INTEGRATION_EVENT_ALLOWED_HOST=hooks.example.test
INSPECTRA_INTEGRATION_EVENT_SIGNING_KEY=<32-bytes-base64url-sin-padding>
INSPECTRA_INTEGRATION_EVENT_SIGNING_KEY_ID=rotation-2026-09
```

Opcionalmente se pueden estrechar los límites ya acotados:

```text
INSPECTRA_INTEGRATION_EVENT_TIMEOUT_SECONDS=5
INSPECTRA_INTEGRATION_EVENT_MAX_CONCURRENCY=2
```

Antes de abrir el socket se resuelven todas las direcciones del host y se
rechaza el destino si falta resolución o alguna dirección no es global. El
cliente ignora proxies del entorno (`trust_env=false`), no sigue redirecciones,
no reintenta dentro de una petición, limita cada espera a diez segundos como
máximo, no supera cuatro entregas concurrentes y descarta respuestas de más de
8 KiB. El endpoint y el host nunca proceden de una API, proyecto o navegador.

## Firma, idempotencia y receptor

Cada petición incluye `X-Inspectra-Event-ID`, `X-Inspectra-Key-ID`,
`X-Inspectra-Timestamp` y `X-Inspectra-Signature`. La firma es
`v1=<hex-HMAC-SHA256>` sobre los bytes ASCII de
`<timestamp>.<cuerpo-json-exacto>`. El receptor debe:

1. seleccionar la clave únicamente por un key ID previamente acordado;
2. rechazar timestamps fuera de su ventana operativa;
3. verificar el HMAC en tiempo constante sobre los bytes recibidos;
4. deduplicar por event ID antes de crear tickets o ejecutar automatización;
5. responder 2xx solo después de persistir su recepción.

Para rotar, publique primero la nueva clave/key ID en el receptor, reinicie
Inspectra con ambos valores nuevos, confirme entregas y retire después la clave
anterior. Las filas pendientes no están ligadas a una clave: se firman con la
clave activa al enviarse. No se admite configurar claves desde la UI.

## Durabilidad, reintentos y operación

El outbox reside en `runtime/integration_event_outbox.sqlite3` con permisos
`0600`; su directorio es `0700`. El ID determinista por
organización/análisis hace idempotente volver a observar el mismo análisis
terminal. Una entrega reclamada tiene lease de 30 s:
si el proceso cae, vuelve a pendiente al expirar. `429`, `5xx`, timeout y fallo
de red se reintentan con backoff acotado; tras cinco intentos, o ante un `4xx`,
redirección, resolución privada o respuesta excesiva, queda `dead` para revisión
del operador. Nunca se registra cuerpo, destino, firma ni excepción.

Los recibos entregados se retienen 30 días y los agotados 90 días; se purgan al
admitir nuevos eventos. La cola tiene un máximo global de 10.000 filas. Alcanzar
ese límite no afecta al análisis autoritativo: se registra un fallo de admisión
sin contenido y se requiere revisar receptor, filas `dead` y capacidad antes de
reanudar la integración.

`GET /operations/integration-events` es una vista agregada, privada y
`no-store`, accesible solo a administradores. Devuelve conteos por workspace,
pero no filas, payloads, destino ni identificadores. La UI distingue apagado,
pendiente, entregado y necesidad de revisión.

Un administrador puede solicitar
`GET /operations/integration-events/replay-preflight`. La respuesta selecciona
como máximo 100 filas `dead` del workspace, informa total/truncado y liga la
selección a un digest opaco válido durante cinco minutos; no lista event IDs ni
payloads. `POST /operations/integration-events/replay` exige CSRF, el mismo
instante/digest y la confirmación literal de que el receptor está sano y
deduplica. Una carrera, cambio o segundo replay falla y obliga a revisar de
nuevo. Las filas vuelven a pendiente con cero intentos y conservan el event ID
original; la acción deja solo un contador agregado en la auditoría.

El outbox es durable frente a reinicio de la aplicación, pero se excluye
deliberadamente del backup: restaurar una cola antigua podría repetir efectos
externos que Inspectra no puede comprobar. El preflight de backup falla si
existe una fila pendiente, en entrega o agotada; solo recibos ya entregados
pueden excluirse. Antes de un backup o restore, deshabilite integraciones y
documente/vacíe las filas pendientes o agotadas. Un
restore comienza sin outbox y no reconstruye eventos históricos; el receptor
debe conservar siempre su deduplicación. La desactivación inmediata consiste en
poner `INSPECTRA_INTEGRATION_EVENTS_ENABLED=false` y reiniciar: no se realizan
entregas y los nuevos análisis no crean eventos.

## Validación y límites conocidos

Las pruebas ordinarias usan `httpx.MockTransport`, reloj y SQLite temporales;
no dependen de Internet. Cubren configuración parcial/hostil, payload mínimo,
HMAC, redirección, `429`/`5xx`/`4xx`, resolución privada, deduplicación, lease,
reintentos, límite de intentos, replay tenant-scoped/expirado/concurrente,
reinicio del store, exclusión de backup, aislamiento de conteos y ausencia de
marcadores sensibles. Un ensayo contra un receptor empresarial real
requiere autorización específica y captura de egress; no se afirma aquí.

Este vertical no es un bus general, SIEM, webhooks configurables por tenant ni
exportación de hallazgos. Añadir tipos de evento o campos exige una nueva versión
del contrato y una revisión explícita de privacidad.
