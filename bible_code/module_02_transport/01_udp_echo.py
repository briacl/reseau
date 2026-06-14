#!/usr/bin/env python3
"""
MODULE 2.1 — Client / Serveur UDP
===================================
Analogie : UDP, c'est envoyer une carte postale. On écrit, on poste,
et on n'a aucune garantie que ça arrive. Pas d'accusé de réception,
pas de connexion, pas d'ordre garanti. Mais c'est RAPIDE.

Différence clé vs TCP :
  - TCP : connexion établie avant l'échange (poignée de main)
  - UDP : on envoie directement, sans établir de session

Cas d'usage réels de UDP : DNS, DHCP, streaming vidéo/audio, jeux en ligne.

Crash Test :
  Terminal 1 : python3 bible_code/module_02_transport/01_udp_echo.py serveur
  Terminal 2 : python3 bible_code/module_02_transport/01_udp_echo.py client
  Ou tester avec netcat : nc -u 127.0.0.1 9999
"""

import socket
import sys

PORT = 9999
HOST = '127.0.0.1'


def serveur():
    """
    Le serveur UDP écoute sur un port et renvoie chaque datagramme en écho.
    SOCK_DGRAM = socket UDP, sans connexion.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, PORT))
        print(f"[SERVEUR UDP] En écoute sur {HOST}:{PORT}")
        print("Renvoie chaque message reçu en écho. Ctrl+C pour arrêter.\n")

        try:
            while True:
                # recvfrom retourne (données, (ip_expéditeur, port_expéditeur))
                # Il n'y a PAS de socket séparé par client : tout passe par le même socket.
                # C'est fondamentalement différent de TCP.
                données, adresse_client = sock.recvfrom(1024)
                message = données.decode('utf-8', errors='replace')
                print(f"[SERVEUR] Reçu de {adresse_client[0]}:{adresse_client[1]} → '{message}'")

                réponse = f"ECHO: {message}".encode('utf-8')
                # sendto : on précise l'adresse à chaque fois, car il n'y a pas de connexion
                sock.sendto(réponse, adresse_client)
        except KeyboardInterrupt:
            print("\nServeur arrêté.")


def client():
    """
    Le client UDP envoie des messages et attend (brièvement) une réponse.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # connect() sur UDP ne crée pas de vraie connexion.
        # Ça configure juste l'adresse par défaut pour les send() suivants.
        sock.connect((HOST, PORT))
        sock.settimeout(2.0)   # On attend max 2s une réponse

        print(f"[CLIENT UDP] Prêt → {HOST}:{PORT}")
        print("Tapez un message. 'quit' pour quitter.\n")

        while True:
            try:
                message = input("Vous : ").strip()
            except EOFError:
                break
            if message.lower() == 'quit':
                break
            if not message:
                continue

            sock.send(message.encode('utf-8'))

            try:
                réponse = sock.recv(1024).decode('utf-8')
                print(f"Serveur : {réponse}")
            except socket.timeout:
                print("[TIMEOUT] Aucune réponse du serveur (paquet perdu ?).")


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in ('serveur', 'client'):
        print("Usage :")
        print("  python3 bible_code/module_02_transport/01_udp_echo.py serveur")
        print("  python3 bible_code/module_02_transport/01_udp_echo.py client")
        sys.exit(1)

    if sys.argv[1] == 'serveur':
        serveur()
    else:
        client()
