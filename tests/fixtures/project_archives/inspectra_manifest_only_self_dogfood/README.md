# Inspectra Manifest-Only Self Dogfood Fixture

This directory is a tiny project-archive input for future passive smoke work.
It mirrors Inspectra at the manifest and config-shape level only.

Allowed use:

- archive this directory for later passive project archive smoke checks;
- use it to exercise dependency inventory and package script reporting;
- use it to exercise Compose topology reporting.

Keep it limited to:

- dependency manifests;
- a sanitized Compose excerpt;
- this usage note.

Do not add:

- application source files;
- test files;
- broad documentation;
- generated uploads, results, or exports;
- deployment-local overrides;
- live host values;
- operator auth material;
- session material;
- client records.

