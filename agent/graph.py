"""
LangGraph Security Pipeline

Defines the agent graph with 4 sequential nodes:
  regex_prefilter → llm_analyzer → self_reflection → gate_decision

State flows through each node, accumulating findings.
LangSmith tracing is attached at the graph level.
"""

import os
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Any

from nodes import (
    regex_prefilter_node,
    llm_analyzer_node,
    self_reflection_node,
    gate_decision_node
)


# ── Graph State Schema ─────────────────────────────────────────────────────────

class SecurityScanState(TypedDict):
    # Input context
    scan_id: str
    pr_number: int
    repo_full_name: str
    head_sha: str
    pr_author: str
    pr_title: str
    diff_content: str

    # Pipeline outputs (accumulate through nodes)
    prefilter_hits: List[dict]       # Fast regex hits
    raw_findings: List[dict]          # LLM initial findings
    critiqued_findings: List[dict]    # After self-reflection
    final_findings: List[dict]        # After gate decision (with gate_action set)

    # Decision
    gate_decision: str                # BLOCK | WARN | ALLOW

    # Observability
    langsmith_run_id: str
    errors: List[str]


# ── Graph Builder ──────────────────────────────────────────────────────────────

def build_security_graph():
    """
    Builds and compiles the LangGraph security analysis pipeline.

    Graph topology (linear — each stage feeds the next):
    
        [START]
           │
           ▼
      regex_prefilter          Fast pattern matching, no LLM cost
           │
           ▼
      llm_analyzer             Claude Sonnet deep semantic analysis
           │
           ▼
      self_reflection          Claude Sonnet critiques its own findings
           │
           ▼
      gate_decision            Applies confidence thresholds, sets BLOCK/WARN/ALLOW
           │
           ▼
        [END]
    """
    builder = StateGraph(SecurityScanState)

    # Register nodes
    builder.add_node("regex_prefilter", regex_prefilter_node)
    builder.add_node("llm_analyzer", llm_analyzer_node)
    builder.add_node("self_reflection", self_reflection_node)
    builder.add_node("gate_decision", gate_decision_node)

    # Wire the linear pipeline
    builder.set_entry_point("regex_prefilter")
    builder.add_edge("regex_prefilter", "llm_analyzer")
    builder.add_edge("llm_analyzer", "self_reflection")
    builder.add_edge("self_reflection", "gate_decision")
    builder.add_edge("gate_decision", END)

    # Compile — attaches LangSmith tracing via env vars automatically
    graph = builder.compile()

    return graph
