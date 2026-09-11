"""Public, source-free compatibility contract for local Inspectra clients."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.version import PRODUCT_VERSION


CLIENT_CAPABILITIES_CONTRACT_VERSION = "2026-09-11.1"
SERVER_VERSION = PRODUCT_VERSION


class ClientContractVersions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    git_snapshot: list[Literal["2026-09-07.1", "2026-09-11.1"]]
    ci_admission: list[Literal["2026-09-06.1"]]
    policy_result: list[Literal["2026-09-07.1"]]
    cli_result: list[Literal["2026-09-07.1"]]
    go_dependency_graph: list[Literal["2026-09-10.1"]]
    cargo_dependency_graph: list[Literal["2026-09-10.2"]]
    composer_dependency_graph: list[Literal["2026-09-10.3"]]
    gradle_dependency_graph: list[Literal["2026-09-10.4"]]
    nuget_dependency_graph: list[Literal["2026-09-10.5"]]
    ci_graph_envelope: list[Literal["2026-09-10.1"]]


class ClientCapabilitiesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-11.1"] = CLIENT_CAPABILITIES_CONTRACT_VERSION
    status: Literal["available"] = "available"
    server_version: str = Field(min_length=1, max_length=32)
    supported_cli_protocols: list[Literal["2026-09-11.1"]]
    contracts: ClientContractVersions


def build_client_capabilities() -> ClientCapabilitiesResponse:
    return ClientCapabilitiesResponse(
        server_version=SERVER_VERSION,
        supported_cli_protocols=[CLIENT_CAPABILITIES_CONTRACT_VERSION],
        contracts=ClientContractVersions(
            git_snapshot=["2026-09-07.1", "2026-09-11.1"],
            ci_admission=["2026-09-06.1"],
            policy_result=["2026-09-07.1"],
            cli_result=["2026-09-07.1"],
            go_dependency_graph=["2026-09-10.1"],
            cargo_dependency_graph=["2026-09-10.2"],
            composer_dependency_graph=["2026-09-10.3"],
            gradle_dependency_graph=["2026-09-10.4"],
            nuget_dependency_graph=["2026-09-10.5"],
            ci_graph_envelope=["2026-09-10.1"],
        ),
    )
