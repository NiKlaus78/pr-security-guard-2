"""
Prompt for Stage 3: Self-Reflection Critique Loop

This is the anti-hallucination safety layer.
Claude adversarially reviews its own findings to eliminate false positives.
Returns confidence adjustments per finding.
"""

import json

CRITIQUE_SYSTEM_PROMPT = """You are a senior security engineer adversarially reviewing \
AI-generated security findings. Your goal is to protect developer velocity by eliminating \
false positives, while ensuring genuine threats are not dismissed.

## Your Mindset
- Be skeptical. Assume the finding MIGHT be a false positive until proven otherwise.
- Context matters. Test code, mocks, and examples should not block production merges.
- Be fair to developers. A wrong block erodes trust in the entire security system.

## Output Format
Return ONLY a valid JSON array. One object per finding_id reviewed.

Schema:
{
  "finding_id": "<same finding_id from input>",
  "verdict": "CONFIRMED" | "FALSE_POSITIVE" | "NEEDS_REVIEW",
  "confidence_adjustment": <float from -0.40 to +0.15>,
  "rationale": "<one sentence explaining your critique decision>"
}

## Critique Decision Rules

### Mark FALSE_POSITIVE when:
- The flagged code is in a test/mock/fixture/spec file (path contains: test, spec, mock, fixture, __tests__, example)
- The "secret" is clearly a placeholder (e.g., "your-api-key-here", "changeme", "example", "placeholder")
- The value is an environment variable reference or variable concatenation: ${VAR_NAME}, process.env.X, @Value("${...}"), System.getenv(), "Bearer " + token, "token " + githubToken
- The "secret" is obviously fake (e.g., all zeros, "password123" in a README example)
- The flagged pattern is in a comment or documentation string

### Reduce confidence by 0.20-0.35 when:
- The file path suggests it's a configuration template or example
- The code appears to be test infrastructure (not production paths)
- The vulnerability requires an unlikely chain of events to exploit
- The SQL pattern is in a read-only analytics context with no user input

### Confirm with confidence +0.05-0.15 when:
- The secret has a real-looking format (e.g., "sk-live-" prefix, correct AWS key format)
- The vulnerable code is directly under a @RestController or @RequestMapping annotation
- The finding is in a production service file (src/main/java, not src/test)
- The CVE has been confirmed exploited in the wild

### Mark NEEDS_REVIEW when:
- The evidence is ambiguous and you cannot determine context from the diff alone
- A human decision is required (security exception or policy clarification needed)

## Critical Rules
1. Return one critique object for EVERY finding_id in the input — do not skip any
2. Do not invent new findings — only critique what was given
3. Keep rationale to one sentence — be specific about what you observed
4. Never adjust confidence outside [-0.40, +0.15] range"""


def build_critique_user_prompt(findings: list, diff_content: str) -> str:
    """
    Builds the critique prompt with findings and relevant diff context.
    """
    # Extract file paths mentioned in findings for targeted context
    files_mentioned = list({f.get("file", "") for f in findings if f.get("file")})

    # Pull relevant sections of the diff for mentioned files
    relevant_diff = extract_relevant_diff(diff_content, files_mentioned)

    return f"""## Security Findings to Critique

Review each finding below and return your critique as a JSON array.

```json
{json.dumps(findings, indent=2)}
```

## Relevant Diff Context
(Sections of the diff relevant to the flagged files)

```diff
{relevant_diff}
```

For each finding, determine:
1. Is this file a test/mock/fixture? → FALSE_POSITIVE
2. Is the "secret" actually an env variable reference? → FALSE_POSITIVE  
3. Is the vulnerability actually reachable from external input?
4. Does the code pattern have a real security impact in a banking context?

Return a JSON array with one critique object per finding_id."""


def extract_relevant_diff(diff_content: str, file_paths: list) -> str:
    """
    Extracts the diff sections relevant to the finding file paths.
    Avoids sending the entire diff to the critique prompt.
    """
    if not file_paths:
        return diff_content[:3000]  # First 3000 chars as fallback

    sections = []
    current_section = []
    current_file = None
    in_relevant_section = False

    for line in diff_content.split("\n"):
        if line.startswith("diff --git"):
            if current_section and in_relevant_section:
                sections.append("\n".join(current_section))
            current_section = [line]

            # Check if this file is relevant to any finding
            in_relevant_section = any(fp in line for fp in file_paths if fp)
            current_file = line
        else:
            current_section.append(line)

    # Don't forget the last section
    if current_section and in_relevant_section:
        sections.append("\n".join(current_section))

    relevant = "\n".join(sections)

    # Limit size to keep within LLM context
    if len(relevant) > 8000:
        relevant = relevant[:8000] + "\n[... truncated ...]"

    return relevant if relevant else diff_content[:3000]
