#!/usr/bin/env python3
"""
MODULE 4.1 — Serveur HTTP "From Scratch"
==========================================
Analogie : un serveur web, c'est juste un programme qui écoute sur
un port TCP, lit du texte, et répond avec du texte. C'est TOUT.

Quand tu tapes http://localhost:8080 dans un navigateur, il envoie :

  GET / HTTP/1.1\r\n
  Host: localhost:8080\r\n
  \r\n
  (ligne vide = fin des headers)

Et le serveur répond :

  HTTP/1.1 200 OK\r\n
  Content-Type: text/html\r\n
  Content-Length: 123\r\n
  \r\n
  <html>...</html>

Ce script implémente exactement ce dialogue, sans framework.

Crash Test :
  Terminal 1 : python3 bible_code/module_04_application/01_http_from_scratch.py
  Navigateur  : http://localhost:8080
  Terminal 2  : curl -v http://localhost:8080
               curl -v http://localhost:8080/status
               curl -v http://localhost:8080/inexistant  <- 404
"""

import socket
import threading
from datetime import datetime

PORT = 8080

STATUS_TEXT = {200: 'OK', 404: 'Not Found', 405: 'Method Not Allowed'}


# ── Contenu des pages ──────────────────────────────────────────────────────────

def page_accueil() -> str:
    return """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Serveur HTTP From Scratch</title>
  <style>
    body { font-family: monospace; max-width: 600px; margin: 60px auto;
           background: #1a1a2e; color: #eee; line-height: 1.7; }
    h1   { color: #00d4ff; }
    code { background: #2a2a4e; padding: 2px 8px; border-radius: 4px; }
    pre  { background: #0d1117; padding: 16px; border-radius: 6px;
           border-left: 3px solid #00d4ff; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>Serveur HTTP fait à la main !</h1>
  <p>Ce serveur est un programme Python qui lit du texte TCP et renvoie du HTML.</p>
  <p>Routes disponibles :</p>
  <pre>GET /         → cette page
GET /status   → JSON avec l'heure du serveur</pre>
  <p>Tester en ligne de commande :</p>
  <pre>curl -v http://localhost:8080/status</pre>
</body>
</html>"""


def page_status() -> str:
    return (
        f'{{"status":"ok","heure":"{datetime.now().strftime("%H:%M:%S")}",'
        f'"serveur":"python-from-scratch","port":{PORT}}}'
    )


def page_404() -> str:
    return "<h1>404 — Page introuvable</h1><p>Cette route n'existe pas.</p>"


# Table de routage : chemin → (code HTTP, Content-Type, fonction)
ROUTES: dict = {
    '/':       (200, 'text/html; charset=utf-8',        page_accueil),
    '/status': (200, 'application/json; charset=utf-8', page_status),
}


# ── Parsing et réponse HTTP ───────────────────────────────────────────────────

def parser_requete(données: bytes) -> tuple:
    """
    Parse les premières lignes d'une requête HTTP.
    La première ligne : MÉTHODE CHEMIN VERSION/CRLF
    Les suivantes    : Clé: Valeur/CRLF
    La ligne vide    : fin des headers (début du body si POST)
    """
    try:
        texte = données.decode('utf-8', errors='replace')
        lignes = texte.split('\r\n')
        méthode, chemin, _ = lignes[0].split(' ', 2)

        headers = {}
        for ligne in lignes[1:]:
            if ': ' in ligne:
                clé, valeur = ligne.split(': ', 1)
                headers[clé.lower()] = valeur.strip()

        return méthode.upper(), chemin.split('?')[0], headers   # on ignore la query string
    except (ValueError, IndexError):
        return 'GET', '/', {}


def forger_reponse(code: int, content_type: str, corps: str) -> bytes:
    """
    Construit une réponse HTTP valide.
    CRLF (\r\n) obligatoire entre les lignes d'en-tête.
    Double CRLF (\r\n\r\n) sépare les headers du corps.
    """
    corps_bytes = corps.encode('utf-8')
    headers = (
        f"HTTP/1.1 {code} {STATUS_TEXT.get(code, 'Unknown')}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(corps_bytes)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    return headers.encode('utf-8') + corps_bytes


# ── Gestion des connexions ────────────────────────────────────────────────────

def gérer_connexion(conn: socket.socket, adresse: tuple) -> None:
    with conn:
        données = conn.recv(8192)
        if not données:
            return

        méthode, chemin, headers = parser_requete(données)
        print(f"{adresse[0]}:{adresse[1]}  {méthode} {chemin}")

        if méthode not in ('GET', 'HEAD'):
            réponse = forger_reponse(405, 'text/plain; charset=utf-8', 'Méthode non autorisée')
        elif chemin in ROUTES:
            code, ctype, fn = ROUTES[chemin]
            # HEAD = mêmes headers que GET, mais pas de corps
            corps = fn() if méthode == 'GET' else ''
            réponse = forger_reponse(code, ctype, corps)
        else:
            réponse = forger_reponse(404, 'text/html; charset=utf-8', page_404())

        conn.sendall(réponse)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', PORT))
        sock.listen(10)

        print(f"=== SERVEUR HTTP FROM SCRATCH — port {PORT} ===")
        print(f"Navigateur : http://localhost:{PORT}")
        print(f"curl       : curl -v http://localhost:{PORT}/status")
        print("Ctrl+C pour arrêter.\n")

        try:
            while True:
                conn, adresse = sock.accept()
                # Un thread par client pour ne pas bloquer sur les connexions lentes
                t = threading.Thread(target=gérer_connexion, args=(conn, adresse), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\nServeur HTTP arrêté.")


if __name__ == '__main__':
    main()
