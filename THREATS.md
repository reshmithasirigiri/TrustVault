# TrustVault threat model

## Assets
- Uploaded document bytes and filenames/categories.
- User credentials and bearer tokens.
- Sharing grants and revocations.
- Audit history and its integrity.

## Trust boundaries
- Browser to FastAPI API over HTTPS in deployment.
- API to PostgreSQL database.
- API to private file storage.
- User-controlled uploads and metadata.

## Threats and mitigations

| Threat | Current mitigation | Remaining limitation |
|---|---|---|
| Unauthenticated access | JWT bearer authentication on protected routes | Token theft remains possible; tokens are stored in browser sessionStorage in this demo |
| User guesses another document ID | Server checks owner or explicit READ/EDIT permission on each download/edit; owner-only delete/share | Add more regression tests and monitoring before production |
| Viewer edits metadata | Metadata endpoint requires owner or EDIT permission | No document-content editing; only metadata changes |
| Permission survives revocation | Future requests query current permission row; revocation deletes grant | Already downloaded copies cannot be recalled |
| Malicious file upload | Extension allow-list, 5 MB limit, random storage filename, path containment check | Extension is not content validation; add MIME/signature checks, antivirus scanning and isolated storage |
| Path traversal | Client filename is reduced to basename; server uses random storage name; resolved storage path is checked | Review all future file endpoints for the same property |
| Password disclosure | Argon2 password hashing; no password returned by API | Enforce rate limits, breached-password checks, reset flow and MFA for real deployment |
| Public privilege escalation | Public registration always assigns `viewer`; admin role provisioned from trusted shell | Secure shell/database credentials and audit admin changes |
| Audit entry modified | Hash chain is verified by admin endpoint | Database superuser can rewrite all entries and recompute hashes; independent external checkpoints are needed for stronger evidence |
| Data loss on free hosting | Migration files tracked; docs recommend durable private storage | Local filesystem may be ephemeral and backups are not configured |
| Secret accidentally committed | `.env` ignored; `.env.example` contains placeholders | Review Git history and rotate any secret that was ever committed/shared |
| Abuse/DoS | 5 MB per-file limit | Add request rate limiting, concurrency caps, quotas and monitoring |

## Security invariants
1. No document is returned to a user unless they own it or hold READ/EDIT permission.
2. Only the owner can grant/revoke permissions or delete a document.
3. Only owner/EDIT can update metadata.
4. Admin audit endpoints are unavailable to non-admin users; admin does not implicitly gain document access.
5. A successful permission revocation blocks subsequent server-side requests.
6. Audit integrity checks are evidence of chain consistency, not proof that a privileged database administrator never altered history.

## Out of scope for this demo
Enterprise SSO/MFA, formal security review, encrypted object storage/key management, antivirus scanning, independent append-only audit anchoring, disaster recovery, compliance certification, and service-level guarantees.
