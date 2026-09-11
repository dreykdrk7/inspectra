# Avisos de software de terceros

Inspectra incorpora las siguientes dependencias en sus artefactos de ejecución.
La tabla está ligada a `backend/requirements.lock` y a los paquetes de
producción de `frontend/package-lock.json`; `make check-release` falla ante una
omisión, duplicado, extra o versión divergente. Las herramientas de desarrollo y
test no forman parte de este inventario runtime.

Las expresiones se obtuvieron de la metadata/licencia incluida por cada
distribución fijada. Los enlaces HTTPS permiten consultar el artefacto y sus
textos de licencia completos. Este inventario facilita revisión y cumplimiento,
pero no constituye asesoramiento jurídico ni reemplaza conservar los textos que
exija el método concreto de redistribución.

| Runtime | Paquete | Versión | Licencia | Distribución/fuente |
| --- | --- | --- | --- | --- |
| Python | annotated-doc | 0.0.5 | MIT | https://pypi.org/project/annotated-doc/0.0.5/ |
| Python | annotated-types | 0.8.0 | MIT | https://pypi.org/project/annotated-types/0.8.0/ |
| Python | anyio | 4.15.0 | MIT | https://pypi.org/project/anyio/4.15.0/ |
| Python | certifi | 2026.7.22 | MPL-2.0 | https://pypi.org/project/certifi/2026.7.22/ |
| Python | cffi | 2.1.1 | MIT-0 | https://pypi.org/project/cffi/2.1.1/ |
| Python | click | 8.5.0 | BSD-3-Clause | https://pypi.org/project/click/8.5.0/ |
| Python | cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause | https://pypi.org/project/cryptography/50.0.1/ |
| Python | cvss | 3.6 | LGPL-3.0-or-later | https://pypi.org/project/cvss/3.6/ |
| Python | fastapi | 0.141.1 | MIT | https://pypi.org/project/fastapi/0.141.1/ |
| Python | h11 | 0.16.0 | MIT | https://pypi.org/project/h11/0.16.0/ |
| Python | httpcore | 1.0.9 | BSD-3-Clause | https://pypi.org/project/httpcore/1.0.9/ |
| Python | httptools | 0.8.0 | MIT | https://pypi.org/project/httptools/0.8.0/ |
| Python | httpx | 0.28.1 | BSD-3-Clause | https://pypi.org/project/httpx/0.28.1/ |
| Python | idna | 3.19 | BSD-3-Clause | https://pypi.org/project/idna/3.19/ |
| Python | packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | https://pypi.org/project/packaging/26.3/ |
| Python | pycparser | 3.0 | BSD-3-Clause | https://pypi.org/project/pycparser/3.0/ |
| Python | pydantic | 2.13.5 | MIT | https://pypi.org/project/pydantic/2.13.5/ |
| Python | pydantic-core | 2.46.5 | MIT | https://pypi.org/project/pydantic-core/2.46.5/ |
| Python | pyjwt | 2.13.0 | MIT | https://pypi.org/project/PyJWT/2.13.0/ |
| Python | python-dotenv | 1.2.3 | BSD-3-Clause | https://pypi.org/project/python-dotenv/1.2.3/ |
| Python | python-multipart | 0.0.32 | Apache-2.0 | https://pypi.org/project/python-multipart/0.0.32/ |
| Python | pyyaml | 6.0.3 | MIT | https://pypi.org/project/PyYAML/6.0.3/ |
| Python | starlette | 1.6.0 | BSD-3-Clause | https://pypi.org/project/starlette/1.6.0/ |
| Python | typing-extensions | 4.16.0 | PSF-2.0 | https://pypi.org/project/typing-extensions/4.16.0/ |
| Python | typing-inspection | 0.4.4 | MIT | https://pypi.org/project/typing-inspection/0.4.4/ |
| Python | uvicorn | 0.52.4 | BSD-3-Clause | https://pypi.org/project/uvicorn/0.52.4/ |
| Python | uvloop | 0.22.1 | Apache-2.0 OR MIT | https://pypi.org/project/uvloop/0.22.1/ |
| Python | watchfiles | 1.2.0 | MIT | https://pypi.org/project/watchfiles/1.2.0/ |
| Python | websockets | 17.1 | BSD-3-Clause | https://pypi.org/project/websockets/17.1/ |
| npm | js-tokens | 4.0.0 | MIT | https://www.npmjs.com/package/js-tokens/v/4.0.0 |
| npm | loose-envify | 1.4.0 | MIT | https://www.npmjs.com/package/loose-envify/v/1.4.0 |
| npm | lucide-react | 0.468.0 | ISC | https://www.npmjs.com/package/lucide-react/v/0.468.0 |
| npm | react | 18.3.1 | MIT | https://www.npmjs.com/package/react/v/18.3.1 |
| npm | react-dom | 18.3.1 | MIT | https://www.npmjs.com/package/react-dom/v/18.3.1 |
| npm | scheduler | 0.23.2 | MIT | https://www.npmjs.com/package/scheduler/v/0.23.2 |

Atención especial: `cvss==3.6` usa LGPL-3.0-or-later. Inspectra lo consume como
biblioteca Python fijada, no copia ni modifica su código fuente, y documenta la
adaptación de redondeo aplicada en tiempo de ejecución. Antes de redistribuir un
artefacto cerrado o empaquetado de otra forma, el responsable debe revisar las
obligaciones aplicables y conservar el texto/fuente correspondiente.
