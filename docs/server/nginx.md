# Nginx

Nginx with PHP-FPM exposes headers through `HTTP_*` server variables. Header order is generally lost. Pass TLS variables explicitly if they are needed:

```nginx
fastcgi_param SSL_PROTOCOL $ssl_protocol;
fastcgi_param SSL_CIPHER $ssl_cipher;
```