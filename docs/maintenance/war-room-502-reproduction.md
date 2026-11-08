# War-room integration failure: production reproduction and fix criteria

## Observed in public MVP (2026-11-08)
- On a sample-alert investigation case, the **War room** panel displayed the full HTML body of a Cloudflare **502 Bad Gateway** response in red text.
- The HTML identified the upstream host `aisoc.rajat.prod.page`. This is a failed upstream integration request; the panel should never display raw HTML or internal infrastructure details.
- The incident report PDF was generated successfully, but its executive summary repeated case-creation workflow text. The report explicitly stated no validated IOCs or MITRE ATT&CK IDs were returned.

## Required targeted fix
1. Locate the Slack/Teams war-room API call and its response rendering in the case detail view.
2. Handle non-2xx responses, network failures, timeouts, and non-JSON/HTML responses before rendering.
3. Show a concise safe error such as “War room unavailable. Please retry later.” Do not render upstream HTML or internal hostnames.
4. Preserve successful war-room creation behavior and avoid retry loops or duplicate creation.
5. Add a narrow regression test for a 502 HTML response; verify no raw HTML appears.
6. Separately, if low-risk, construct the report executive summary from incident facts rather than concatenated workflow titles. Preserve its uncertainty and safety warnings.

## Validation / release
- Validate on this branch, then update the draft PR with the actual code changes and test results.
- Do not merge, redeploy, modify production credentials, or enable live response actions without separate approval.
- No fix is claimed by this investigation note alone.
