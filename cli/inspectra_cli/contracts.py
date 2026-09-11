"""Versioned contracts required before the CLI may process private source."""

CLI_PROTOCOL_VERSION = "2026-09-11.1"
REQUIRED_SERVER_CONTRACTS = {
    "git_snapshot": "2026-09-11.1",
    "ci_admission": "2026-09-06.1",
    "policy_result": "2026-09-07.1",
    "cli_result": "2026-09-07.1",
    "go_dependency_graph": "2026-09-10.1",
    "cargo_dependency_graph": "2026-09-10.2",
    "composer_dependency_graph": "2026-09-10.3",
    "gradle_dependency_graph": "2026-09-10.4",
    "nuget_dependency_graph": "2026-09-10.5",
    "ci_graph_envelope": "2026-09-10.1",
}
