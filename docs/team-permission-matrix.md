# Matriz de permisos y aislamiento de equipos

Esta matriz describe el contrato de autorización del modo
`private_team_lightweight_users`. No añade SSO ni convierte una instalación
privada en servicio multiempresa público. El ámbito efectivo siempre es la
organización seleccionada en una sesión vigente; cambiar rol, revocar membresía
o cambiar de organización invalida/rota la sesión y el CSRF anterior.

## Capacidades cerradas

| Rol | Leer workspace | Modificar proyectos y hallazgos | Administrar workspace |
| --- | --- | --- | --- |
| Reader | Sí | No | No |
| Maintainer | Sí | Sí | No |
| Administrator | Sí | Sí | Sí |

El backend implementa estas capacidades como `workspace_read`,
`project_mutate` y `workspace_admin`. Un rol o capacidad desconocidos se
deniegan. `reader` solo puede usar GET y cinco POST de consulta exactos:
cartera, tendencias, informe de tendencias, búsqueda de remediación e informe
de remediación. Esos POST siguen exigiendo CSRF y no mutan estado.

## Matriz por flujo

| Flujo | Reader | Maintainer | Administrator |
| --- | --- | --- | --- |
| Ver proyectos, análisis, inventario, hallazgos, comparación e informes | Leer/exportar | Leer/exportar | Leer/exportar |
| Buscar cartera, tendencias y remediación | Sí, con CSRF | Sí, con CSRF | Sí, con CSRF |
| Importar fuente, crear/repetir/cancelar análisis y gestionar triage | Denegado | Permitido | Permitido |
| Proponer identidad pública exacta | Denegado | Permitido | Permitido |
| Aprobar o revocar identidad pública | Denegado | Denegado | Permitido |
| Invitar, cambiar rol, revocar miembro o crear organización | Denegado | Denegado | Permitido |
| Ver auditoría, ejecutar retención o gestionar credenciales de automatización | Denegado | Denegado | Permitido |
| Exportaciones Active sensibles y cambios de autorización | Denegado | Según el control específico del flujo | Permitido |

Las rutas administrativas vuelven a comprobar `workspace_admin`; no dependen
solo de que el frontend oculte un botón. Las mutaciones de proyecto aceptan
`project_mutate`, pero cada store vuelve a filtrar por el ID de organización de
la sesión. Un ID perteneciente a otra organización responde como recurso no
encontrado, sin confirmar su existencia.

## Invariantes verificables

- Toda mutación con sesión exige CSRF; un token anterior al cambio de workspace
  o rol deja de ser válido.
- Los recursos persistidos se consultan con `organization_id`; no existe un
  bypass administrativo global entre organizaciones.
- Un reader no obtiene permisos de escritura aunque construya manualmente una
  petición que la UI no ofrece.
- Los permisos de automatización forman otra frontera: scopes, proyecto y
  organización se validan antes de ejecutar la ruta y no heredan el rol de una
  sesión humana.
- La auditoría registra actor, rol, organización y recurso opaco, no contraseñas,
  tokens, código, rutas, targets ni nombres de paquetes.

La regresión obligatoria combina la matriz pura deny-by-default, el allowlist
exacto de POST de lectura, sesiones de reader/maintainer/administrator, cambio
de rol con invalidación y dos organizaciones con recursos propios. Cualquier
nueva familia de endpoints debe declarar en esta tabla si es lectura,
`project_mutate` o `workspace_admin` y añadir al menos un caso permitido y uno
denegado. No se amplía el allowlist de reader mediante prefijos o parámetros de
ruta.
