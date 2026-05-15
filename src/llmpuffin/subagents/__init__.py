"""Subagent definitions for the audit agent.

Each subagent is defined in its own module. Import `ALL` for the full list.
"""

from llmpuffin.subagents.finding_validator import FINDING_VALIDATOR
from llmpuffin.subagents.function_analyzer import FUNCTION_ANALYZER
from llmpuffin.subagents.threat_model_auditor import THREAT_MODEL_AUDITOR

ALL = [FUNCTION_ANALYZER, THREAT_MODEL_AUDITOR, FINDING_VALIDATOR]
