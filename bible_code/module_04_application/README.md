# Module 4 — Couche Application (HTTP / Proxy)

**Prérequis :** Python 3.8+, pas de `sudo` (ports > 1024)

| Fichier | Port | Ce qu'il fait |
|---|---|---|
| `01_http_from_scratch.py` | 8080 | Serveur HTTP minimal avec routage |
| `02_proxy_http.py` | 8888 | Proxy HTTP avec filtrage |
| `03_proxy_https_connect.py` | 8889 | Proxy HTTP + HTTPS (CONNECT) |

## Tests rapides

```bash
# Serveur HTTP
python3 01_http_from_scratch.py
curl -v http://localhost:8080
curl -v http://localhost:8080/status
curl -v http://localhost:8080/nope      # → 404

# Proxy HTTP
python3 02_proxy_http.py
curl --proxy http://127.0.0.1:8888 http://example.com
curl --proxy http://127.0.0.1:8888 http://httpbin.org/headers

# Proxy HTTP+HTTPS
python3 03_proxy_https_connect.py
curl --proxy http://127.0.0.1:8889 http://example.com
curl --proxy http://127.0.0.1:8889 https://httpbin.org/get
```

## Différence structurelle : HTTP direct vs HTTP proxié

```
Direct : GET /index.html HTTP/1.1
          Host: example.com

Proxié : GET http://example.com/index.html HTTP/1.1
          Host: example.com
```

Le proxy détecte l'URL absolue dans la première ligne pour savoir où se connecter.

## Pourquoi select() dans le tunnel HTTPS ?

`select()` surveille plusieurs sockets en même temps.
Sans lui, il faudrait deux boucles bloquantes → deux threads.
Avec lui, un seul thread suffit pour le relais bidirectionnel.
