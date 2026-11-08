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

## Implemented on draft PR #20
- Evidence-first summary built from structured state with explicit labels for unverified alerts, candidate ATT&CK mappings, automated timelines, forensic hypotheses and unexecuted response actions.
- AEGIS AI HTML title/footer branding, Markdown summary bullets and print-friendly table/page styling.
- Safeguards for unsupported IOC-blocking proposals and rationales that assert unconfirmed threat-actor attribution.
- Deterministic regression tests covering sparse and evidence-rich states, HTML escaping, branding, actor rationale and singular/plural indicator-blocking phrases.

## Remaining acceptance checks
- Confirm the final branch head passes CI. The preceding head f5013749 passed all 33 workflows, including the dedicated PDF render workflow.
- **Completed for the sample report:** GitHub Actions run 42484863964 generated artifact `incident-report-pdf-smoke` (WeasyPrint 70.0, 2 A4 pages). Both pages were visually inspected: correct AEGIS AI title/footer, readable IOC/timeline tables, no clipped content, and clean section breaks. Tight executive-summary bullet spacing was found and improved in a follow-up commit; the updated artifact still needs visual confirmation. This is a sample PDF, not a production report or a stress test of long tables.
- Confirm report persistence/regeneration behavior before expecting historical reports to change after deployment. Inspect dense/long tables and multipage evidence separately if those layouts are release-blocking.
- Obtain explicit merge and deployment approval. This draft PR must not change production.


## Final sample-PDF review (2026-11-08)

- Commit `ec73f068`: dedicated PDF workflow run [42485720075](https://github.com/Rajat-7271/AEGIS-AI/actions/runs/42485720075) passed and uploaded `incident-report-pdf-smoke` (artifact ID `13618929736`).
- Downloaded the artifact, rendered both A4 pages to images, and inspected the title, summary list spacing, timeline and IOC tables, section breaks, attribution text, and footer. No visible clipping; the attribution bullet now begins on its own line.
- This validates the deterministic sample only. Historical stored report HTML, long-table stress cases, and production behavior remain unverified. No deployment was performed.
