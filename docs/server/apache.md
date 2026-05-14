# Apache

Apache may expose `apache_request_headers()` or `getallheaders()`. Header order is not guaranteed. Deployments using `mod_remoteip` should document whether `REMOTE_ADDR` is rewritten.