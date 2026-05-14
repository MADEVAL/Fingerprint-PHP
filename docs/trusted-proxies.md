# Trusted Proxies

Never trust `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, or CDN client IP headers from arbitrary clients.

The library uses this rule:

1. Start with `REMOTE_ADDR`.
2. If `REMOTE_ADDR` is not trusted, ignore all forwarded headers.
3. If `REMOTE_ADDR` is trusted, parse only configured trusted headers.
4. Validate every IP address.
5. Pick the first untrusted upstream address as the client address.

Common presets exist for Cloudflare, Fastly, Akamai, AWS load balancers, and generic Nginx reverse proxies. Keep provider CIDR ranges current in your application when using CDN presets.