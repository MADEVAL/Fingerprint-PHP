# Limitations

Server-side fingerprinting is limited by deployment reality.

1. Header order is usually lost in classic PHP-FPM deployments.
2. JA3/JA4 TLS fingerprints are not available to normal PHP behind Nginx, Apache, or IIS.
3. Client Hints can be missing because of browser policy.
4. CDN and reverse proxies can rewrite headers.
5. IP addresses can change frequently.
6. Fingerprint collisions and fingerprint drift are expected.

Use the result as one signal in a broader security decision.