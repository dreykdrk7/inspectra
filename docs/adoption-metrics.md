# Métricas privadas locales de adopción

Inspectra no recopila telemetría de adopción por defecto. El operador puede
activar explícitamente `INSPECTRA_ADOPTION_METRICS_ENABLED=true` para conocer
fricción agregada en un conjunto cerrado de recorridos. No existe transporte,
endpoint de descarga, SDK analítico ni envío a terceros: los datos permanecen
en `results/adoption_metrics.sqlite3` dentro del volumen privado.

## Contrato y privacidad

El contrato `2026-09-10.1` agrega por día UTC exclusivamente:

- flujo y fase cerrados (onboarding de archivo/SBOM, admisión CI/revisión,
  consulta OSV y exportaciones de proyecto, tendencias o remediación);
- resultado `succeeded`, `invalid`, `denied`, `throttled` o `failed` derivado
  del estado HTTP;
- intervalo de duración `<100 ms`, `<500 ms`, `<2 s`, `<10 s`, `<60 s` o
  `>=60 s`;
- contador.

Nunca recibe ni conserva ID de usuario, organización, proyecto, análisis o
petición; ruta concreta, query, cabecera, cookie, IP, user agent, nombre,
repositorio, componente, código, evidencia, secreto, payload, timestamp exacto
o duración exacta. Las rutas no incluidas en el catálogo se ignoran. El SQLite
es `0600`, usa schema cerrado, máximo 8.192 filas/16 MiB y 90 días de retención.
Readiness solo depende de él cuando el opt-in está activo. Backup valida su
esquema y dimensiones para impedir que texto arbitrario sea aceptado como una
métrica.

La agregación diaria aún puede revelar que la instancia tuvo actividad y, con
volúmenes pequeños, un contador puede corresponder a una sola acción. Por eso
el valor predeterminado es `false`, no se desglosa por tenant y el archivo debe
tratarse como metadato operativo sensible.

## Activación y exportación local

1. Revise el catálogo anterior y la política interna de privacidad.
2. Configure `INSPECTRA_ADOPTION_METRICS_ENABLED=true` solo en el backend y
   reinícielo. No necesita token, URL ni credencial externa.
3. Verifique `/ready`; un store inválido hace fallar esa comprobación cuando la
   función está activa, sin afectar las escrituras autoritativas del producto.
4. Exporte únicamente desde el host/volumen autorizado, con el backend detenido
   o sobre una copia offline coherente:

   ```bash
   PYTHONPATH=backend python -m app.adoption_metrics_cli \
     --data-dir /ruta/privada/inspectra-data \
     --local-export-confirmed
   ```

La salida JSON repite las garantías de privacidad y no modifica el store. No
la publique automáticamente: revísela y aplique la retención de su organización.
Desactivar la variable detiene nuevas observaciones; no borra silenciosamente
el histórico. Para retirarlo, detenga todos los backends, conserve o elimine de
forma controlada `adoption_metrics.sqlite3` según su política y vuelva a arrancar
con el valor desactivado.

## Límites conocidos

Estas métricas muestran puntos de fricción HTTP, no adopción humana, éxito de
remediación, calidad de hallazgos ni productividad. Un `2xx` significa que la
fase HTTP fue aceptada, no que un análisis posterior terminase correctamente.
No deben emplearse para evaluar personas, comparar organizaciones ni inferir
riesgo. Añadir un nuevo flujo requiere ampliar el catálogo en código, pruebas de
canarios sensibles y una nueva revisión del contrato; nunca se admite una ruta
o etiqueta suministrada por el usuario.
