#!/usr/bin/env python3
"""
MODULE 2.2 — Client / Serveur TCP + Three-Way Handshake
=========================================================
Analogie : TCP, c'est un appel téléphonique. Avant d'échanger quoi
que ce soit, les deux partis établissent un canal (la sonnerie + décroché).
C'est le Three-Way Handshake :

  Client → Serveur : SYN   "Je veux me connecter, mon numéro de séquence est X"
  Serveur → Client : SYN-ACK "OK, je confirme X, mon numéro de séquence est Y"
  Client → Serveur : ACK   "Je confirme Y, canal ouvert."

Ce handshake garantit que les deux partis sont prêts AVANT le premier mot.

Pour voir le handshake en temps réel :
  sudo tcpdump -i lo tcp port 9998 -n

Crash Test :
  Terminal 1 : python3 bible_code/module_02_transport/02_tcp_handshake.py serveur
  Terminal 2 : python3 bible_code/module_02_transport/02_tcp_handshake.py client
  Observateur : sudo tcpdump -i lo tcp port 9998 -n
"""

import socket
import sys

PORT = 9998
HOST = '127.0.0.1'


def serveur():
    """
    SOCK_STREAM = socket TCP.
    accept() bloque jusqu'à la fin du Three-Way Handshake.
    Chaque appel à accept() retourne un NOUVEAU socket dédié au client.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # SO_REUSEADDR : évite "Address already in use" si on relance rapidement
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))

        # listen(backlog) : taille de la file d'attente des connexions entrantes
        sock.listen(5)
        print(f"[SERVEUR TCP] En écoute sur {HOST}:{PORT}")
        print("Voir le handshake : sudo tcpdump -i lo tcp port 9998 -n\n")

        try:
            while True:
                print("En attente d'un client (SYN attendu)...")

                # accept() NE RETOURNE QUE QUAND le SYN-ACK a été acquitté.
                # Le kernel a déjà géré les 3 étapes avant qu'on arrive ici.
                conn, adresse = sock.accept()
                print(f"[SERVEUR] Handshake terminé avec {adresse[0]}:{adresse[1]} ✓")
                print(f"          (SYN → SYN-ACK → ACK automatiquement géré par le kernel)")

                with conn:
                    while True:
                        données = conn.recv(1024)
                        if not données:
                            break
                        message = données.decode('utf-8')
                        print(f"[SERVEUR] Message : '{message}'")
                        conn.sendall(f"Reçu : '{message}'".encode('utf-8'))

                # La fermeture du `with` envoie FIN → ACK pour clore proprement
                print("[SERVEUR] Connexion fermée (FIN → ACK échangés).\n")
        except KeyboardInterrupt:
            print("\nServeur arrêté.")


def client():
    """
    connect() envoie le SYN et bloque jusqu'à la fin du handshake.
    À la sortie de connect(), le canal TCP est entièrement établi.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"[CLIENT TCP] Connexion à {HOST}:{PORT}...")
        print("             (envoi SYN → attente SYN-ACK → envoi ACK)")

        # Le Three-Way Handshake se passe entièrement ici, dans connect()
        sock.connect((HOST, PORT))
        print("[CLIENT] Canal TCP établi ✓")
        print("Tapez vos messages. 'quit' ou 'q' pour fermer la connexion.\n")

        while True:
            try:
                message = input("Vous : ").strip()
            except EOFError:
                break
            if message.lower() in ('quit', 'q'):
                break
            if not message:
                continue

            sock.sendall(message.encode('utf-8'))
            réponse = sock.recv(1024).decode('utf-8')
            print(f"Serveur : {réponse}")

    # La fermeture du `with` envoie FIN pour clore le canal
    print("[CLIENT] Connexion fermée.")


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in ('serveur', 'client'):
        print("Usage :")
        print("  python3 bible_code/module_02_transport/02_tcp_handshake.py serveur")
        print("  python3 bible_code/module_02_transport/02_tcp_handshake.py client")
        sys.exit(1)

    if sys.argv[1] == 'serveur':
        serveur()
    else:
        client()
