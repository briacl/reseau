#!/usr/bin/env python3
"""
MODULE 1.2 — Forger et envoyer une requête ARP
================================================
Analogie : ARP, c'est crier dans une pièce "Qui a l'adresse 192.168.1.X ?".
Ce script construit le cri octet par octet et écoute qui répond.

Structure d'une trame ARP complète (42 octets) :

  -- En-tête Ethernet (14 octets) --
  [6]  MAC destination    FF:FF:FF:FF:FF:FF  (broadcast = tout le monde entend)
  [6]  MAC source         notre propre MAC
  [2]  EtherType          0x0806 = ARP

  -- Paquet ARP (28 octets) --
  [2]  HW Type            0x0001 = Ethernet
  [2]  Protocol Type      0x0800 = IPv4
  [1]  HW Addr Length     6 (octets d'une MAC)
  [1]  Proto Addr Length  4 (octets d'une IPv4)
  [2]  Opcode             1=Request / 2=Reply
  [6]  Sender MAC         notre MAC
  [4]  Sender IP          notre IP
  [6]  Target MAC         00:00:00:00:00:00 (inconnu, c'est ce qu'on cherche)
  [4]  Target IP          l'IP qu'on veut résoudre

Crash Test :
  sudo python3 bible_code/module_01_liaison/02_arp_forge.py
  -> interface : eth0 (ou ens33, wlan0...)
  -> IP cible  : l'IP de votre passerelle (ex: 192.168.1.1)
"""

import socket
import struct
import fcntl

BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'

# Codes ioctl Linux pour lire les infos d'une interface réseau
SIOCGIFHWADDR = 0x8927   # Lire l'adresse MAC
SIOCGIFADDR   = 0x8915   # Lire l'adresse IP


def get_mac_interface(sock, interface):
    """Récupère les 6 octets bruts de la MAC de notre interface."""
    info = fcntl.ioctl(
        sock.fileno(),
        SIOCGIFHWADDR,
        struct.pack('256s', interface[:15].encode())
    )
    return info[18:24]


def get_ip_interface(sock, interface):
    """Récupère l'IP de notre interface sous forme de string."""
    info = fcntl.ioctl(
        sock.fileno(),
        SIOCGIFADDR,
        struct.pack('256s', interface[:15].encode())
    )
    return socket.inet_ntoa(info[20:24])


def forger_arp_request(mac_src: bytes, ip_src: str, ip_cible: str) -> bytes:
    """
    Construit la trame complète Ethernet + ARP en octets bruts.
    struct.pack '!' = big-endian réseau, 'H' = 2 octets, 'B' = 1 octet.
    """
    # --- En-tête Ethernet ---
    eth = BROADCAST_MAC + mac_src + struct.pack('!H', 0x0806)

    # --- Paquet ARP ---
    arp = struct.pack(
        '! H H B B H',
        1,       # HW Type = Ethernet
        0x0800,  # Protocol Type = IPv4
        6,       # MAC length
        4,       # IP length
        1        # Opcode 1 = Request
    )
    arp += mac_src                        # Sender MAC
    arp += socket.inet_aton(ip_src)       # Sender IP
    arp += b'\x00' * 6                    # Target MAC : inconnu
    arp += socket.inet_aton(ip_cible)     # Target IP : ce qu'on cherche

    return eth + arp


def decoder_arp_reply(trame: bytes):
    """
    Retourne (ip, mac) si la trame est un ARP Reply, sinon None.
    Le paquet ARP commence à l'octet 14 (après les 14 octets Ethernet).
    """
    if len(trame) < 42:
        return None
    arp = trame[14:42]
    _, _, _, _, opcode = struct.unpack('! H H B B H', arp[:8])
    if opcode != 2:   # 2 = Reply
        return None
    sender_mac = ':'.join(f'{b:02X}' for b in arp[8:14])
    sender_ip  = socket.inet_ntoa(arp[14:18])
    return sender_ip, sender_mac


def main():
    interface = input("Interface réseau (ex: eth0, ens33, wlan0) : ").strip()
    ip_cible  = input("IP à résoudre  (ex: 192.168.1.1)          : ").strip()

    try:
        # 0x0806 = ETH_P_ARP : on ne capture que les trames ARP
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sock.bind((interface, 0))
    except PermissionError:
        print("Droits root requis : sudo python3 bible_code/module_01_liaison/02_arp_forge.py")
        return
    except OSError as e:
        print(f"Interface '{interface}' introuvable. ({e})")
        return

    mac_src = get_mac_interface(sock, interface)
    ip_src  = get_ip_interface(sock, interface)
    mac_src_str = ':'.join(f'{b:02X}' for b in mac_src)

    print(f"\nNous sommes : {ip_src} ({mac_src_str})")
    print(f"Envoi ARP Request → Qui a {ip_cible} ?\n")

    trame = forger_arp_request(mac_src, ip_src, ip_cible)
    sock.send(trame)

    print("Attente de la réponse ARP (timeout 3s)...")
    sock.settimeout(3.0)
    try:
        while True:
            data, _ = sock.recvfrom(65535)
            résultat = decoder_arp_reply(data)
            if résultat and résultat[0] == ip_cible:
                print(f"\n[RÉPONSE] {résultat[0]} → MAC : {résultat[1]}")
                break
    except socket.timeout:
        print(f"[TIMEOUT] Aucune réponse de {ip_cible} (hôte absent ou filtré).")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
