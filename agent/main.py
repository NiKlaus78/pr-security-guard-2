"""
PR Security Guard — Python Agent Service
FastAPI entry point that receives scan requests from the Spring Boot webhook service
and runs them through the LangGraph security analysis pipeline.
"""

import time
import uuid
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from graph import build_security_graph
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
# Enable DEBUG for CVE checker so we can see exactly what OSV returns
logging.getLogger("tools.cve_checker").setLevel(logging.DEBUG)
log = logging.getLogger(__name__)


# ── Request / Response Models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    pr_number: int
    repo_full_name: str
    head_sha: str
    base_sha: str
    pr_author: str
    pr_title: str
    diff_content: str
    pom_xml_content: str = ""    # Full pom.xml content when present in diff


class ScanResponse(BaseModel):
    scan_id: str
    langsmith_run_id: str
    findings: list
    gate_decision: str      # BLOCK | WARN | ALLOW
    summary: str
    duration_ms: int


# ── App Lifecycle ─────────────────────────────────────────────────────────────

security_graph = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global security_graph
    log.info("Building LangGraph security pipeline...")
    security_graph = build_security_graph()
    log.info("Security pipeline ready.")
    yield
    log.info("Agent service shutting down.")


app = FastAPI(
    title="PR Security Guard Agent",
    description="LangGraph-powered security analysis pipeline",
    version="1.0.0",
    lifespan=lifespan
)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/scan", response_model=ScanResponse)
async def scan_pr(request: ScanRequest):
    """
    Runs the full LangGraph security pipeline on a PR diff.
    Returns structured findings with gate decision.
    """
    scan_id = str(uuid.uuid4())[:8]
    start_ms = int(time.time() * 1000)

    log.info(f"[{scan_id}] Scan started | repo={request.repo_full_name} PR=#{request.pr_number}")

    if not request.diff_content.strip():
        return ScanResponse(
            scan_id=scan_id,
            langsmith_run_id="",
            findings=[],
            gate_decision="ALLOW",
            summary="No diff content to scan.",
            duration_ms=0
        )

    try:
        # Build initial state for the LangGraph pipeline
        initial_state = {
            "scan_id": scan_id,
            "pr_number": request.pr_number,
            "repo_full_name": request.repo_full_name,
            "head_sha": request.head_sha,
            "pr_author": request.pr_author,
            "pr_title": request.pr_title,
            "diff_content": request.diff_content,
            "prefilter_hits": [],
            "cve_findings": [],
            "pom_xml_content": request.pom_xml_content,
            "raw_findings": [],
            "critiqued_findings": [],
            "final_findings": [],
            "gate_decision": "ALLOW",
            "langsmith_run_id": "",
            "errors": []
        }

        # Run the graph — this executes all pipeline stages sequentially
        result = await security_graph.ainvoke(initial_state)

        duration_ms = int(time.time() * 1000) - start_ms

        log.info(
            f"[{scan_id}] Scan complete | "
            f"findings={len(result['final_findings'])} "
            f"decision={result['gate_decision']} "
            f"duration={duration_ms}ms"
        )

        return ScanResponse(
            scan_id=scan_id,
            langsmith_run_id=result.get("langsmith_run_id", ""),
            findings=result["final_findings"],
            gate_decision=result["gate_decision"],
            summary=build_summary(result),
            duration_ms=duration_ms
        )

    except Exception as e:
        log.error(f"[{scan_id}] Scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/health")
async def health():
    return {"status": "UP", "service": "pr-security-guard-agent"}


@app.get("/presentation")
async def get_presentation():
    import os
    path = "/app/pr-security-guard-presentation.html"
    if not os.path.exists(path):
        path = "pr-security-guard-presentation.html"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


# ── Helpers ───────────────────────────────────────────────────────────────────

def build_summary(result: dict) -> str:
    findings = result.get("final_findings", [])
    decision = result.get("gate_decision", "ALLOW")

    active = [f for f in findings if f.get("gate_action") != "DISCARD"]
    critical = sum(1 for f in active if f.get("severity") == "CRITICAL")
    high = sum(1 for f in active if f.get("severity") == "HIGH")
    medium = sum(1 for f in active if f.get("severity") == "MEDIUM")
    discarded = len(findings) - len(active)

    return (
        f"Decision: {decision} | "
        f"Active findings: {len(active)} "
        f"(critical={critical}, high={high}, medium={medium}) | "
        f"Discarded by critique: {discarded}"
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
