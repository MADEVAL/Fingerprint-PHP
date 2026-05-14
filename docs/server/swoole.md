# Swoole

Swoole and OpenSwoole use long-lived workers. Build `RequestContext` from the runtime request object instead of `$_SERVER`, reset per-request state, and avoid static mutable caches tied to one request.