# Snapshots offline de avisos públicos

Inspectra puede correlacionar avisos previamente obtenidos por un operador sin
dar acceso a Internet al backend. El importador no descarga contenido, no
acepta URL, no ejecuta el bundle y no activa el egress. La identidad completa
de cada consulta se valida en memoria y se sustituye por la misma clave SHA-256
irreversible que usa la caché antes de persistirla.

Esta vía no convierte un origen no confiable en confiable. Antes de importar,
el operador debe obtener el bundle desde una fuente autorizada, calcular su
SHA-256 por un canal independiente y revisar la procedencia. El contrato actual
no incluye firma digital; el checksum aporta integridad y vinculación exacta,
no autoría.

## Contrato soportado

El contrato `2026-09-09.1` admite un objeto JSON estricto, sin claves
duplicadas, con esta forma:

```json
{
  "contract_version": "2026-09-09.1",
  "kind": "inspectra_public_advisory_offline_bundle",
  "created_at": "2026-09-09T08:00:00Z",
  "expires_at": "2026-09-10T08:00:00Z",
  "entries": [
    {
      "provider": "osv",
      "identities": [
        {"ecosystem": "npm", "name": "nombre-publico", "version": "1.2.3"}
      ],
      "pages": 1,
      "response": {"results": [{"vulns": []}]}
    }
  ]
}
```

Los proveedores admitidos son `osv`, `github_advisories`, `nvd` y
`cisa_kev`. GHSA y NVD usan `lookup_id` exacto; CISA KEV no admite identidad de
proyecto. Los normalizadores existentes vuelven a validar que la respuesta
pertenece a la consulta exacta. Un bundle parcialmente inválido se rechaza
entero: no se publica una cobertura incompleta como limpia.

Límites cerrados del contrato:

- archivo regular, no symlink, de hasta 16 MiB;
- entre 1 y 5.000 entradas, sin claves proveedor/consulta duplicadas;
- hasta 100 identidades exactas por entrada OSV;
- 2 MiB por respuesta y 16 MiB acumulados;
- vigencia máxima de 30 días y fecha de expiración posterior a la importación;
- solo nombres y versiones aceptados por la política pública de Inspectra; los
  scopes npm y las identidades privadas, ambiguas o no correlacionables se
  rechazan;
- ninguna ruta, URL privada, hash de proyecto, credencial, archivo o código se
  copia al snapshot activo.

## Importación, inspección y rollback

Detenga escrituras administrativas concurrentes al directorio de datos y use
la misma imagen/versión de backend que leerá el snapshot. Sustituya las rutas y
el digest por valores revisados explícitamente; no use una URL como origen:

```sh
python -m app.offline_advisory_cli import \
  --bundle /ruta/operador/avisos.json \
  --expected-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --advisories-dir /data/results/public_advisories \
  --operator-confirmed

python -m app.offline_advisory_cli status \
  --advisories-dir /data/results/public_advisories
```

La salida contiene únicamente estado, versión, identificadores SHA-256,
fechas, número de entradas y proveedores. No imprime la ruta del bundle ni
identidades de paquete. La publicación escribe primero un historial inmutable
y reemplaza atómicamente `offline/active.json`.

Volver a importar el mismo snapshot devuelve `snapshot_already_imported` y no
reescribe el historial ni el puntero activo. Para seleccionar de nuevo un
snapshot ya retenido use exclusivamente `activate`; una colisión con contenido
distinto falla como conflicto.

Para revertir a un snapshot retenido y todavía vigente:

```sh
python -m app.offline_advisory_cli activate \
  --snapshot-id 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --advisories-dir /data/results/public_advisories \
  --operator-confirmed
```

La interfaz muestra el prefijo del identificador offline activo o usado. Con
egress deshabilitado, solo se resuelven consultas cuya clave exacta exista en
el snapshot; una ausencia queda deshabilitada/no disponible, nunca se interpreta
como «sin vulnerabilidades». Al expirar, la evidencia puede servir como fallback
`stale` durante un máximo adicional de 30 días y jamás vuelve a considerarse
fresca. Después deja de resolverse.

## Amenazas cubiertas y límites conocidos

- La importación no abre red y no permite SSRF mediante URL, host o ruta.
- Checksum, esquema cerrado, cuotas, validación del proveedor y publicación
  atómica evitan activar silenciosamente archivos truncados, cruzados o
  parcialmente válidos.
- La aplicación no persiste una copia separada del payload de consulta: guarda
  respuestas públicas acotadas, claves digest y tiempos. Una respuesta del
  proveedor sí puede contener la identidad pública normalizada que sustenta el
  aviso; nunca contiene metadatos del proyecto.
- El identificador de snapshot prueba qué conjunto normalizado se usó, pero no
  sustituye una firma, transparencia del proveedor ni revisión humana.
- El historial ocupa almacenamiento hasta que la política de retención lo
  elimine; supervise el volumen y no importe snapshots innecesarios.
- Esta capacidad no valida una integración real con el proveedor. Un adaptador
  ejercitado solo con bundle/fixture debe seguir etiquetado como validado con
  fixtures.

Las pruebas ordinarias usan fixtures y `MockTransport` o ejecutan con red
bloqueada. Deben cubrir checksum incorrecto, JSON duplicado/corrupto, respuesta
parcial, identidad privada, expiración, activación anterior, aislamiento de
claves y ausencia total de peticiones HTTP.
