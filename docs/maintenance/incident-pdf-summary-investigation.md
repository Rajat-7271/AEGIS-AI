# Investigation PDF executive-summary improvement

## Confirmed code path
- Frontend `apps/web/src/lib/api.ts` downloads `GET /api/v1/cases/{caseId}/investigations/{runId}/report.pdf`.
- API endpoint `services/api/app/api/v1/endpoints/cases.py::case_investigation_pdf` validates that the run belongs to the requested case, proxies `GET /api/v1/investigations/{runId}/report.html` to the agents service, and converts returned HTML to PDF using WeasyPrint.
- **Therefore the API PDF conversion endpoint is not the source of executive-summary prose.** Change the agents service's report HTML / structured summary generation, not the PDF conversion wrapper.

## Reproduction / observed defect
A generated investigation report executive summary repeated case-creation workflow text instead of describing concrete incident findings. The report noted that no validated IOCs or MITRE ATT&CK IDs were returned. Those limitations must remain explicit.

## Acceptance criteria
1. Executive summary is based on verified incident facts (case identity, timeline, affected assets, observations, analyst/agent findings and response status) rather than a concatenation of workflow titles.
2. Do not invent indicators, ATT&CK techniques, severity, root cause, attribution or remediation outcomes. Distinguish observed facts, hypotheses, missing evidence and pending actions.
3. Where evidence is insufficient, state that clearly and avoid boilerplate repetitions.
4. Preserve tenant isolation and existing PDF generation/download behavior.
5. Add deterministic unit tests for: evidence-rich case; sparse/no-IOC case; no duplicated workflow prose; stable output; escaped untrusted text.
6. Run relevant backend tests and CI; keep PR draft until validation. No production changes.

## Scope
This document traces the report generation path. It is not an implementation or a claim that the PDF summary is fixed.
