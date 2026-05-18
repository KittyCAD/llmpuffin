"""
Threat model data structures and TOML parser.

The threat model follows the TRAIL methodology (Trail of Bits):
- System is decomposed into **components** organized in a hierarchy
- Components are grouped into **trust zones** based on shared security controls
- **Trust boundaries** exist where security controls gate connections between zones
- **Connections** describe data/control flow crossing trust boundaries
- **Threat scenarios** describe how an adversary could exploit a connection
  crossing a trust boundary (connection-actor combination = "threat actor path")

See: https://blog.trailofbits.com/2025/02/28/threat-modeling-the-trail-of-bits-way/
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Self

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class StrideCategory(StrEnum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class Component(BaseModel):
    """A system component (service, library, data store, etc.).

    Components can be nested hierarchically: a top-level "backend" component
    might contain sub-components like "api_server" and "database".
    """

    id: str
    name: str
    description: str = ""
    # GitHub repo path (e.g. "KittyCAD/engine") — used to determine
    # which components are local to the current audit run
    repo: str = ""
    # Hierarchical: components can contain sub-components
    components: list[Component] = Field(default_factory=list)
    # Tags for filtering / grouping (e.g. "external", "privileged")
    tags: list[str] = Field(default_factory=list)


class TrustZone(BaseModel):
    """A trust zone groups components that share the same security posture.

    Trust boundaries exist at the edges of trust zones — anywhere that
    security controls gate connections between components.  Components
    inside the same zone trust each other implicitly.
    """

    id: str
    name: str
    description: str = ""
    # IDs of components that belong to this zone
    component_ids: list[str] = Field(default_factory=list)
    # Trust zones can nest (e.g. "internal" zone contains "database" sub-zone)
    trust_zones: list[TrustZone] = Field(default_factory=list)


class Connection(BaseModel):
    """A connection between two components that crosses a trust boundary.

    Connections are the attack surface: each one is a place where an
    adversary might escalate privilege by moving from one trust zone
    to another.
    """

    id: str
    source_component_id: str
    destination_component_id: str
    description: str = ""
    # Protocol / mechanism (e.g. "HTTPS", "gRPC", "shared filesystem")
    protocol: str = ""
    # Whether this connection crosses a trust boundary (auto-derived if omitted)
    crosses_trust_boundary: bool = True


class ThreatScenario(BaseModel):
    """A potential way an adversary could exploit a connection crossing a trust boundary.

    Each scenario is a specific "threat actor path" — a pairing of a
    threat actor persona with a connection they could abuse.  Scenarios
    should describe the attack vector, not just the impact.

    Layered mitigations are recommended: several overlapping controls per
    scenario, since any single mitigation could fail or be subverted.
    """

    id: str
    name: str
    description: str = ""
    # Which connection(s) this scenario targets
    connection_ids: list[str] = Field(default_factory=list)
    # Which component(s) are affected
    affected_component_ids: list[str] = Field(default_factory=list)
    category: StrideCategory
    severity: Severity
    # Existing mitigations the model should verify
    mitigations: list[str] = Field(default_factory=list)


class ThreatModel(BaseModel):
    """Top-level threat model aggregating all elements.

    A threat model is a living document that should be updated as the system
    evolves.  It serves as the primary input to llmpuffin's agentic review:
    the agent uses it to prioritize which code paths to examine.

    Threat models are loaded from a directory of .toml files.  Each file
    can contribute components, trust zones, connections, and/or threat
    scenarios.  All files are parsed and merged together, so you can
    organize by subsystem, team, or however makes sense.
    """

    components: list[Component] = Field(default_factory=list)
    trust_zones: list[TrustZone] = Field(default_factory=list)
    connections: list[Connection] = Field(default_factory=list)
    threat_scenarios: list[ThreatScenario] = Field(default_factory=list)

    @classmethod
    def from_toml(cls, path: Path) -> Self:
        """Load a threat model from a single TOML file."""
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return cls(**data)

    @classmethod
    def from_dir(cls, directory: Path) -> Self:
        """Load and merge all .toml files in a directory into one threat model."""
        model = cls()
        for toml_path in sorted(directory.glob("*.toml")):
            partial = cls.from_toml(toml_path)
            model.components.extend(partial.components)
            model.trust_zones.extend(partial.trust_zones)
            model.connections.extend(partial.connections)
            model.threat_scenarios.extend(partial.threat_scenarios)
        return model

    def get_component(self, component_id: str) -> Component | None:
        """Recursively find a component by ID."""
        return _find_component(self.components, component_id)

    def get_trust_zone_for_component(self, component_id: str) -> TrustZone | None:
        """Find which trust zone a component belongs to."""
        return _find_zone_for_component(self.trust_zones, component_id)

    def connections_crossing_boundaries(self) -> list[Connection]:
        """Return only connections that cross trust boundaries."""
        result = []
        for conn in self.connections:
            src_zone = self.get_trust_zone_for_component(conn.source_component_id)
            dst_zone = self.get_trust_zone_for_component(conn.destination_component_id)
            if src_zone != dst_zone or conn.crosses_trust_boundary:
                result.append(conn)
        return result

    def components_for_repo(self, repo: str) -> list[Component]:
        """Return components that belong to a given repo."""
        return [c for c in self.components if c.repo == repo]

    def neighbor_component_ids(self, repo: str) -> set[str]:
        """Return component IDs connected to any component in the given repo."""
        local_ids = {c.id for c in self.components_for_repo(repo)}
        neighbors: set[str] = set()
        for conn in self.connections:
            if conn.source_component_id in local_ids:
                neighbors.add(conn.destination_component_id)
            if conn.destination_component_id in local_ids:
                neighbors.add(conn.source_component_id)
        return neighbors - local_ids

    def view_for_repo(self, repo: str) -> ThreatModelView:
        """Return a perspective view of the threat model from a specific repo.

        Local components: components whose repo matches.
        Neighbor components: components connected to local ones (in other repos).
        Relevant connections: any connection touching a local component.
        Relevant threats: any threat affecting a local or neighbor component.
        """
        local = self.components_for_repo(repo)
        local_ids = {c.id for c in local}
        neighbor_ids = self.neighbor_component_ids(repo)
        all_relevant_ids = local_ids | neighbor_ids

        neighbors = [c for c in self.components if c.id in neighbor_ids]

        connections = [
            c
            for c in self.connections
            if c.source_component_id in local_ids
            or c.destination_component_id in local_ids
        ]

        threats = [
            t
            for t in self.threat_scenarios
            if any(cid in all_relevant_ids for cid in t.affected_component_ids)
        ]

        return ThreatModelView(
            local_components=local,
            neighbor_components=neighbors,
            connections=connections,
            threat_scenarios=threats,
            trust_zones=self.trust_zones,
        )


class ThreatModelView(BaseModel):
    """A perspective view of the threat model from a specific repo."""

    local_components: list[Component] = Field(default_factory=list)
    neighbor_components: list[Component] = Field(default_factory=list)
    connections: list[Connection] = Field(default_factory=list)
    threat_scenarios: list[ThreatScenario] = Field(default_factory=list)
    trust_zones: list[TrustZone] = Field(default_factory=list)


def _find_component(components: list[Component], cid: str) -> Component | None:
    for c in components:
        if c.id == cid:
            return c
        found = _find_component(c.components, cid)
        if found:
            return found
    return None


def _find_zone_for_component(zones: list[TrustZone], cid: str) -> TrustZone | None:
    for z in zones:
        if cid in z.component_ids:
            return z
        found = _find_zone_for_component(z.trust_zones, cid)
        if found:
            return found
    return None
