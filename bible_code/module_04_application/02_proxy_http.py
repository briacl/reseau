#!/usr/bin/env python3
"""
MODULE 4.2 — Proxy HTTP
=========================
Analogie : le proxy est un assistant silencieux. Au lieu d'aller chercher
ta pizza toi-même, tu demandes à l'assistant. Il va chez le pizzaiolo à ta place,
récupère la pizza, et te la ramène. Le pizzaiolo ne sait pas que c'est toi.

Schéma :
  Navigateur ─[requête HTTP]→ PROXY ─[même requête]→ Serveur web
  Navigateur ←─[réponse]───── PROXY ←─[réponse]───── Serveur web

Différence clé entre une requête normale et une requête proxiée :
  Normale  : GET /index.html HTTP/1.1
  Via proxy: GET http://example.com/index.html HTTP/1.1   ← URL absolue !

Le proxy détecte cette URL absolue pour savoir où se connecter.

Fonctionnalités de ce script :
  - Relais TCP bidirectionnel (requête + réponse)
  - Filtrage de sites (liste noire)
  - Log de chaque requête

Crash Test :
  Terminal 1 : python3 bible_code/module_04_application/02_proxy_http.py
  Terminal 2 : curl --proxy http://127.0.0.1:8888 http://example.com
               curl --proxy http://127.0.0.1:8888 http://httpbin.org/get
  Firefox    : Préférences → Proxy manuel → HTTP: 127.0.0.1 port 8888
"""

import socket
import threading

PROXY_PORT = 8888
BUFFER     = 4096
TIMEOUT    = 15

# Sites bloqués : la requête retourne 403 sans aller sur le réseau
LISTE_NOIRE: set = {'pub.example.com', 'tracking.example.net'}


def extraire_host_port(requête: bytes) -> tuple:
    """
    Extrait la méthode HTTP, l'hôte et le port depuis la première ligne.
    Requête proxiée : GET http://example.com:8080/path HTTP/1.1
    """
    try:
        première_ligne = requête.split(b'\r\n')[0].decode('utf-8')
        méthode, url, _ = première_ligne.split(' ', 2)

        # Retirer le schéma http://
        if url.startswith('http://'):
            url = url[7:]

        # Séparer host[:port] du chemin
        hôte_port, *_ = url.split('/', 1)

        if ':' in hôte_port:
            hôte, port = hôte_port.split(':', 1)
            return méthode, hôte, int(port)
        return méthode, hôte_port, 80
    except (ValueError, IndexError):
        return None, None, None


def relayer(source: socket.socket, destination: socket.socket) -> None:
    """
    Relaie les bytes de source → destination jusqu'à fermeture de connexion.
    On ne lit pas le contenu : on est un tuyau.
    """
    try:
        while True:
            données = source.recv(BUFFER)
            if not données:
                break
            destination.sendall(données)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def gérer_client(conn_client: socket.socket, adresse: tuple) -> None:
    with conn_client:
        requête = conn_client.recv(BUFFER)
        if not requête:
            return

        méthode, hôte, port = extraire_host_port(requête)
        if not hôte:
            return

        print(f"{adresse[0]}:{adresse[1]}  {méthode or '???'} {hôte}:{port}")

        # Vérification liste noire
        if hôte in LISTE_NOIRE:
            print(f"  → BLOQUÉ")
            conn_client.sendall(
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Content-Type: text/plain\r\n\r\n"
                b"Acces bloque par le proxy.\n"
            )
            return

        # Connexion vers le serveur cible
        try:
            conn_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn_serveur.settimeout(TIMEOUT)
            conn_serveur.connect((hôte, port))
        except OSError as e:
            print(f"  → Impossible de joindre {hôte}:{port} ({e})")
            return

        with conn_serveur:
            # Transmettre la requête originale au serveur
            conn_serveur.sendall(requête)

            # Relay bidirectionnel : deux threads, un par sens
            # serveur → client (la page HTML)
            t_down = threading.Thread(target=relayer, args=(conn_serveur, conn_client), daemon=True)
            # client → serveur (éventuels bytes supplémentaires : corps POST, etc.)
            t_up   = threading.Thread(target=relayer, args=(conn_client, conn_serveur),  daemon=True)

            t_down.start()
            t_up.start()
            t_down.join()
            t_up.join()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', PROXY_PORT))
        sock.listen(20)

        print(f"=== PROXY HTTP — port {PROXY_PORT} ===")
        print(f"curl   : curl --proxy http://127.0.0.1:{PROXY_PORT} http://example.com")
        print(f"Bloqués: {LISTE_NOIRE}")
        print("Ctrl+C pour arrêter.\n")

        try:
            while True:
                conn, adresse = sock.accept()
                threading.Thread(target=gérer_client, args=(conn, adresse), daemon=True).start()
        except KeyboardInterrupt:
            print("\nProxy HTTP arrêté.")


if __name__ == '__main__':
    main()
