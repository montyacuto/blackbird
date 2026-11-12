"""Ordinary evidence adapter for the Trivy-to-LiteLLM development house."""

from __future__ import annotations

from blackbird_core import ActionSpec

from cci_prototype.shoot_house.adapter import OrdinaryActionAdapter

from .target import TrivyLiteLLMTarget


CAPABILITIES = (
    ActionSpec("describe"),
    ActionSpec("list_incidents"),
    ActionSpec("read_incident", {"incident_id": "incident_id"}),
    ActionSpec("list_release_channels"),
    ActionSpec("read_release_channel", {"release_channel_id": "release_channel_id"}),
    ActionSpec("list_downstreams"),
    ActionSpec("read_downstream", {"downstream_id": "downstream_id"}),
    ActionSpec("list_gateways"),
    ActionSpec("read_gateway", {"gateway_id": "gateway_id"}),
    ActionSpec("list_runs"),
    ActionSpec("read_run", {"run_id": "run_id"}, cost=2),
)


class TrivyLiteLLMAdapter(OrdinaryActionAdapter):
    def __init__(self, target: TrivyLiteLLMTarget | None = None):
        super().__init__(target or TrivyLiteLLMTarget(), CAPABILITIES)
