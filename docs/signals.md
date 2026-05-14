# Signals

Signals are collected from HTTP headers, network context, TLS/server variables, cookies explicitly allowed by the application, and derived browser profiles.

Each signal has:

1. Name.
2. Type.
3. Normalized value.
4. Hashed value.
5. Weight.
6. Stability.
7. Sensitivity.
8. Inclusion reason.

Denied by default: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, API key headers, auth token headers, CSRF/XSRF token headers, request bodies, and full query strings.