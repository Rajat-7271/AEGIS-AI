# Verified self-service login-email change — implementation contract

Status: design only; **not implemented or enabled**. PR #24 must not be merged solely on this document.

## Current constraints
- The login query selects the globally unique `users.email` column; `User` also stores `is_verified` and `sessions_revoked_at`.
- Existing Mailgun support is for action-approval emails, **not** a general account-identity verification service. Do not reuse approval bearer tokens as login-email credentials.
- Never set `users.email` from a profile form or from a token without an atomic, single-use verification transaction.
- A new address requested by the operator is not yet a verified login identity.

## Required workflow
1. Authenticated user submits the proposed email **and current password**. Enforce MFA step-up when enrolled, rate limits per principal/IP/address, normalized address validation, and generic non-enumerating errors.
2. Under tenant/user-scoped authorization, create a pending request bound to the immutable user ID, tenant ID, normalized proposed address, and current email. Store only a hash of a cryptographically random verification token. Expire it quickly (suggest 30 minutes); invalidate previous pending requests.
3. Send a verification link to the proposed mailbox via an explicitly configured, tested mail transport. Do not claim success if delivery is not configured; do not log the link or token. Notify the original mailbox that a change was requested, with a safe cancellation/recovery path.
4. The confirmation endpoint verifies token hash, expiry, unused state, user and tenant binding, and that the account's original email still matches. Lock the user and pending request, recheck global email uniqueness, then atomically set `users.email`, consume the token, and advance `sessions_revoked_at`.
5. Notify both addresses after completion, write a tenant-scoped security audit event without secrets, and require fresh sign-in. Reject replay, cross-tenant use, expired tokens, inactive users, duplicate addresses, and concurrent confirmations.
6. Recovery must rely on independently verified identity, not merely the new mailbox. Keep an operator-controlled rollback procedure and protect it with audit logging.

## Required tests before enabling
- No email mutation on request, delivery failure, invalid/expired/replayed token, incorrect password, or MFA failure.
- Single-use confirmation under concurrent requests and uniqueness collision.
- Old tokens invalidated after success; new sign-in works only with verified address.
- Session revocation, audit trail, notification redaction, rate limiting, tenant isolation, and OpenAPI export.
- End-to-end email delivery in a sandbox provider, with production sender-domain verification checked separately.

## Deployment guard
Implement in a separate reviewed change or a clearly isolated feature-flagged portion of PR #24. A migration, backend deployment, working outbound email, and rollback plan are mandatory before enabling it. Do not manually edit production credentials or the users table as a substitute for verification.
