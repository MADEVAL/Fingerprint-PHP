# Privacy

Fingerprints can be personal or pseudonymous data. Applications must decide their own legal basis, consent model, retention period, user access flow, and deletion flow.

The library defaults to privacy-aware behavior:

1. Raw values are disabled in safe output.
2. Full IP addresses are not included in `strict` or `balanced` profiles.
3. Cookies are ignored unless explicitly allowlisted.
4. Authorization and token-like headers are always denied.
5. The final fingerprint is HMAC-protected with an application secret.

Use `strict` for data minimization, `balanced` for most security workflows, and `maximum` only after a deliberate product and legal review.