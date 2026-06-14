#!/usr/bin/env python3
"""
MODULE 4.3 — Proxy HTTP + HTTPS (méthode CONNECT)
===================================================
Analogie : pour HTTPS, le proxy ne peut pas lire le contenu (chiffré par TLS).
Il se transforme en "tuyau aveugle" : il perce un tunnel entre le client
et le serveur, et laisse les bytes chiffrés passer sans y toucher.
C'est un videur qui ouvre la porte sans regarder ce que tu portes.

Séquence CONNECT (tout en clair, avant TLS) :
  Client → Proxy : CONNECT api.example.com:443 HTTP/1.1
                   Host: api.example.com:443
                   [ligne vide]

  Proxy  → Client: HTTP/1.1 200 Connection Established
                   [ligne vide]

  Client ←→ Proxy ←→ Serveur : [flux TLS chiffré — le proxy est aveugle]

Ce script gère les DEUX cas en un seul proxy :
  - HTTP  (GET, POST...)    → relais avec lecture possible du contenu
  - HTTPS (CONNECT + :443)  → tunnel aveugle bidirectionnel

Crash Test :
  Terminal 1 : python3 bible_code/module_04_application/03_proxy_https_connect.py
  Terminal 2 :
    curl --proxy http://127.0.0.1:8889 http://example.com        ← HTTP
    curl --proxy http://127.0.0.1:8889 https://httpbin.org/get   ← HTTPS
  Observer les deux cas avec :
    sudo tcpdump -i lo tcp port 8889 -A -n
"""

import socket
import threading
import select

PROXY_PORT = 8889
BUFFER     = 8192
TIMEOUT    = 15


def lire_headers(sock: socket.socket) -> bytes:
    """Lit les bytes jusqu'à la ligne vide (fin des headers HTTP)."""
    données = b''
    while b'\r\n\r\n' not in données:
        chunk = sock.recv(4096)
        if not chunk:
            break
        données += chunk
    return données


def parser_premiere_ligne(requête: bytes) -> tuple:
    """
    Extrait (méthode, hôte, port) de la première ligne HTTP.
    CONNECT example.com:443 → ('CONNECT', 'example.com', 443)
    GET http://example.com/ → ('GET', 'example.com', 80)
    """
    try:
        ligne = requête.split(b'\r\n')[0].decode('utf-8')
        méthode, cible, _ = ligne.split(' ', 2)

        if méthode.upper() == 'CONNECT':
            # CONNECT target:port → hôte et port directement
            hôte, port = cible.rsplit(':', 1)
            return méthode.upper(), hôte, int(port)

        # GET http://host[:port]/path → extraire hôte et port
        url = cible
        if url.startswith('http://'):
            url = url[7:]
        hôte_port = url.split('/')[0]
        if ':' in hôte_port:
            hôte, port = hôte_port.split(':', 1)
            return méthode.upper(), hôte, int(port)
        return méthode.upper(), hôte_port, 80
    except (ValueError, IndexError):
        return None, None, None


def tunnel_aveugle(sock_a: socket.socket, sock_b: socket.socket) -> None:
    """
    Pont bidirectionnel entre deux sockets.
    select() surveille les deux sockets en même temps et déclenche
    le transfert dès que l'un d'eux a des données à lire.
    Aucune interprétation du contenu : on est aveugle.
    """
    sockets = [sock_a, sock_b]
    while True:
        lisibles, _, en_erreur = select.select(sockets, [], sockets, TIMEOUT)
        if en_erreur or not lisibles:
            break
        for s in lisibles:
            dest = sock_b if s is sock_a else sock_a
            try:
                données = s.recv(BUFFER)
                if not données:
                    return   # L'un des côtés a fermé la connexion
                dest.sendall(données)
            except OSError:
                return


def gérer_client(conn_client: socket.socket, adresse: tuple) -> None:
    requête = lire_headers(conn_client)
    if not requête:
        conn_client.close()
        return

    méthode, hôte, port = parser_premiere_ligne(requête)
    if not hôte:
        conn_client.close()
        return

    print(f"{adresse[0]}:{adresse[1]}  {méthode} {hôte}:{port}")

    # Connexion TCP vers le serveur cible (hôte final, pas le proxy)
    try:
        conn_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_serveur.settimeout(TIMEOUT)
        conn_serveur.connect((hôte, port))
    except OSError as e:
        print(f"  → Connexion impossible vers {hôte}:{port} : {e}")
        conn_client.close()
        return

    if méthode == 'CONNECT':
        # Cas HTTPS : on confirme le tunnel, puis on devient aveugle
        # Sans ce 200, le navigateur n'entame pas le handshake TLS
        conn_client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        print(f"  → Tunnel TLS ouvert (proxy aveugle dès maintenant)")
        # À partir d'ici : bytes chiffrés TLS, le proxy ne voit que des octets opaques
        tunnel_aveugle(conn_client, conn_serveur)
    else:
        # Cas HTTP classique : on transmet la requête et on relaie la réponse
        conn_serveur.sendall(requête)
        tunnel_aveugle(conn_client, conn_serveur)

    conn_client.close()
    conn_serveur.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', PROXY_PORT))
        sock.listen(20)

        print(f"=== PROXY HTTP+HTTPS — port {PROXY_PORT} ===")
        print(f"HTTP  : curl --proxy http://127.0.0.1:{PROXY_PORT} http://example.com")
        print(f"HTTPS : curl --proxy http://127.0.0.1:{PROXY_PORT} https://httpbin.org/get")
        print(f"Combo : curl --proxy http://127.0.0.1:{PROXY_PORT} -L https://httpbin.org/get")
        print("Ctrl+C pour arrêter.\n")

        try:
            while True:
                conn, adresse = sock.accept()
                threading.Thread(target=gérer_client, args=(conn, adresse), daemon=True).start()
        except KeyboardInterrupt:
            print("\nProxy HTTP+HTTPS arrêté.")


if __name__ == '__main__':
    main()
