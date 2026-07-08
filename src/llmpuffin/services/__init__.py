"""Service layer — all DB-backed operations."""

from llmpuffin.services.coverage import (
    CoverageTracker,
    build_coverage_tree,
    load_coverage_for_run,
)
from llmpuffin.services.embeddings import (
    FindingCluster,
    backfill_embeddings,
    cluster_findings,
    embed_finding,
    find_similar_findings,
    find_similar_global,
)
from llmpuffin.services.finding import FindingService
from llmpuffin.services.github import report_finding_to_github, ReportResult
from llmpuffin.services.profile import ProfileService
from llmpuffin.services.run import RunService
from llmpuffin.services.sarif import export_sarif_for_run
from llmpuffin.services.skill import SkillService
from llmpuffin.services.threat_model import ThreatModelService

__all__ = [
    "CoverageTracker",
    "FindingCluster",
    "FindingService",
    "ProfileService",
    "ReportResult",
    "RunService",
    "SkillService",
    "ThreatModelService",
    "backfill_embeddings",
    "build_coverage_tree",
    "cluster_findings",
    "embed_finding",
    "export_sarif_for_run",
    "find_similar_findings",
    "find_similar_global",
    "load_coverage_for_run",
    "report_finding_to_github",
]
