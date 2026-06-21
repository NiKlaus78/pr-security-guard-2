# Automated PR Security Guard

Enterprise-grade AI agent that intercepts pull requests, scans for security violations,
runs a self-reflection critique loop, and blocks merges on confirmed threats.

## Architecture

```
GitHub PR Event
      │
      ▼
Spring Boot Webhook Service (Java)
      │  receives PR payload, extracts git diff
      ▼
Python LangGraph Agent
  ├── Stage 1: Regex Pre-filter (fast, cheap)
  ├── Stage 2: LLM Security Analyzer (Mistral Codestral)
  ├── Stage 3: Self-Reflection Critique (Mistral Codestral)
  └── Stage 4: Gate Decision → GitHub Status API
      │
      ▼
PostgreSQL (audit log) + LangSmith (tracing)
```

## Project Structure

```
pr-security-guard/
├── webhook-service/          # Spring Boot — receives GitHub webhooks
│   └── src/main/java/com/security/guard/
│       ├── controller/       # WebhookController.java
│       ├── service/          # DiffExtractorService.java, AgentCallerService.java
│       ├── model/            # PrPayload.java, SecurityFinding.java
│       └── config/           # SecurityConfig.java
├── agent/                    # Python LangGraph agent
│   ├── main.py               # FastAPI entry point
│   ├── graph.py              # LangGraph pipeline definition
│   ├── nodes.py              # Each pipeline stage as a node
│   ├── prompts/              # All LLM prompt templates
│   │   ├── analyzer.py
│   │   ├── critique.py
│   │   └── formatter.py
│   └── tools/
│       ├── regex_scanner.py  # Fast pre-filter patterns
│       └── cve_checker.py    # OSV/NVD API integration
├── policy/
│   └── security-policy.yaml  # Company security rules
├── docker/
│   ├── Dockerfile.webhook
│   ├── Dockerfile.agent
│   └── docker-compose.yml
└── .github/
    └── workflows/
        └── pr-security-guard.yml  # GitHub Actions trigger
```

## Quick Start

### Prerequisites
- Java 17+, Maven 3.8+
- Python 3.11+
- Docker & Docker Compose
- Mistral API key
- LangSmith API key (free tier works)
- GitHub webhook secret

### 1. Set environment variables
```bash
cp .env.example .env
# Fill in: MISTRAL_API_KEY, LANGSMITH_API_KEY, GITHUB_WEBHOOK_SECRET, DATABASE_URL
```

### 2. Start with Docker Compose
```bash
docker-compose -f docker/docker-compose.yml up -d
```

### 3. Register webhook in GitHub
- Go to your repo → Settings → Webhooks → Add webhook
- Payload URL: `https://your-domain/webhook/github`
- Content type: `application/json`
- Secret: (same as GITHUB_WEBHOOK_SECRET in .env)
- Events: Pull requests

### 4. Open a test PR with a hardcoded secret
The agent will automatically scan and post findings as PR review comments.

## Environment Variables

| Variable | Description |
|---|---|
| `MISTRAL_API_KEY` | Your Mistral API key |
| `LANGSMITH_API_KEY` | LangSmith tracing key |
| `LANGSMITH_PROJECT` | LangSmith project name |
| `GITHUB_TOKEN` | GitHub token for posting comments |
| `GITHUB_WEBHOOK_SECRET` | Secret for validating webhook signatures |
| `DATABASE_URL` | PostgreSQL connection string |
| `AGENT_SERVICE_URL` | Internal URL of the Python agent service |
| `CONFIDENCE_THRESHOLD` | Min confidence to block merge (default: 0.85) |
