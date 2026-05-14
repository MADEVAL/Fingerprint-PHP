# FrankenPHP

FrankenPHP can run PHP applications as a modern application server and may expose request data differently from classic PHP-FPM deployments. Prefer request-object integration where available, avoid global mutable request state, and treat any edge-derived TLS or proxy fingerprint values as trusted only when they are injected by your own infrastructure.

Header order may be closer to runtime order than in PHP-FPM, but it should still be treated as an optional low-to-medium reliability signal.