# Caddy

Caddy usually behaves as a reverse proxy in front of PHP-FPM. Treat it like a generic trusted proxy: configure trusted proxy CIDRs explicitly, pass HTTPS and client IP headers deliberately, and do not rely on original header order.