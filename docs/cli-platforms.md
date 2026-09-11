# Matriz de plataformas de Inspectra CLI

Esta matriz distingue soporte demostrado de portabilidad esperada. Un wheel
`py3-none-any` no constituye por sí solo evidencia multiplataforma.

| Entorno | Estado de soporte | Evidencia actual | Límites |
| --- | --- | --- | --- |
| Linux x86_64, CPython 3.12 | Soportado para la candidatura validada | Suite CLI en contenedor Debian/Python 3.12 con Git real; wheel y sdist instalados sin monorepo; TAR repetido byte a byte; Unicode, espacios y CRLF | Gitleaks 8.x y Git deben estar en `PATH`; el operador debe verificar el artefacto y ejecutar `inspectra doctor` |
| macOS nativo | No validado; no se anuncia como soportado | Solo funciones unitarias independientes del SO para ruta convencional de configuración | Faltan runner real, Git/Gitleaks nativos, permisos, señales, filesystem sensible a mayúsculas y E2E desde artefacto |
| Windows nativo | No validado; no se anuncia como soportado | Solo funciones unitarias independientes del SO para ruta convencional de configuración | Faltan runner real, ACL, creación TAR, paths largos/Unicode, señales, Git/Gitleaks y E2E PowerShell |
| WSL2 | No validado separadamente | Comparte la base Linux, pero no se ha probado sobre filesystem Windows montado | Use solo como experimento local y no como plataforma declarada |

La implementación invoca Git y Gitleaks mediante listas de argumentos, nunca
mediante shell, por lo que espacios y metacaracteres no se reinterpretan. El
snapshot conserva exactamente los bytes del blob Git: no convierte CRLF/LF ni
normaliza nombres Unicode. El orden del TAR se basa en los bytes UTF-8 del path,
con tiempos, propietario y modos normalizados. Paths no UTF-8, absolutos,
ambiguos o con traversal fallan cerrados.

Los clones shallow/partial no amplían la red de forma implícita: no se ejecuta
`fetch` y `GIT_NO_LAZY_FETCH=1` impide materializar objetos prometidos durante
la lectura. El usuario debe aportar localmente el commit completo autorizado.

Los ejemplos de la documentación actual usan sintaxis POSIX. No se ofrecen aún
instrucciones PowerShell ni instaladores nativos. La habilitación de macOS y
Windows exige una matriz real que construya el artefacto una vez, verifique su
digest, lo instale en runners limpios y compare inventario, lista de paths y
digest contractual. Esa matriz remota permanece separada del soporte Linux
acreditado. `SEC-012` y `PROD-130` ya están completadas, pero `PROD-167`
conserva el trabajo bloqueado hasta disponer de runners macOS/Windows y una
autorización específica.
