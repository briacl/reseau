#!/usr/bin/env python3
"""
MODULE 3.2 — Mini-Serveur DHCP (DISCOVER → OFFER)
===================================================
Analogie : DHCP, c'est l'accueil d'un hôtel.
  Client (nouveau venu)  : "Y a-t-il un hôtel ici ?"       → DISCOVER (broadcast)
  Serveur (hôtel)        : "Oui ! Voici ta chambre 100"    → OFFER
  Client                 : "J'accepte la chambre 100"      → REQUEST
  Serveur                : "Chambre 100 confirmée, c'est à toi" → ACK

Ce script implémente uniquement DISCOVER → OFFER pour rester lisible.
C'est le cœur du protocole : comprendre l'attribution d'IP.

Structure d'un message DHCP (RFC 2131) :
  [1]  op     : 1=BOOTREQUEST (client), 2=BOOTREPLY (serveur)
  [1]  htype  : 1=Ethernet
  [1]  hlen   : 6 (longueur d'une adresse MAC)
  [1]  hops   : nombre de relais traversés
  [4]  xid    : Transaction ID (corrèle DISCOVER/OFFER/REQUEST/ACK)
  [2]  secs   : secondes depuis le début de la procédure
  [2]  flags  : bit 15 = broadcast flag
  [4]  ciaddr : IP client actuelle (0.0.0.0 si aucune)
  [4]  yiaddr : "Your IP" = l'IP proposée par le serveur
  [4]  siaddr : IP du serveur DHCP
  [4]  giaddr : IP du relais (0 si pas de relay agent)
  [16] chaddr : adresse MAC du client (paddée à 16 octets)
  [64] sname  : nom du serveur (optionnel)
  [128] file  : nom fichier de boot (PXE, optionnel)
  [4]  magic  : 0x63825363 (cookie magique DHCP obligatoire)
  [N]  options: liste d'options TLV (Type, Length, Value)

ATTENTION : ne pas lancer sur un réseau avec un vrai serveur DHCP actif.
            Utiliser une VM en mode réseau host-only ou un réseau isolé.

Crash Test :
  sudo python3 bible_code/module_03_services/02_mini_dhcp.py
  puis sur une VM Linux : sudo dhclient -v eth0
  ou observer avec     : sudo tcpdump -i any udp port 67 or port 68 -n
"""

import socket
import struct

SERVEUR_IP  = '192.168.50.1'
MASQUE      = '255.255.255.0'
PASSERELLE  = '192.168.50.1'
DNS         = '8.8.8.8'
BAIL_DUREE  = 3600   # secondes

POOL_IPS = [f'192.168.50.{i}' for i in range(100, 120)]   # 20 adresses dispo

# Table d'attribution : mac_str → ip_str
pool_attribue: dict = {}


def attribuer_ip(mac_str: str) -> str | None:
    """Réutilise l'IP déjà attribuée, sinon prend la première libre du pool."""
    if mac_str in pool_attribue:
        return pool_attribue[mac_str]
    for ip in POOL_IPS:
        if ip not in pool_attribue.values():
            pool_attribue[mac_str] = ip
            return ip
    return None   # Pool épuisé


def mac_vers_str(octets: bytes) -> str:
    return ':'.join(f'{b:02X}' for b in octets[:6])


def forger_dhcp_offer(discover: bytes, ip_offerte: str, trans_id: int) -> bytes:
    """
    Construit un message DHCP OFFER.
    Les options DHCP sont au format TLV : [1 octet type][1 octet longueur][N octets valeur]
    L'option 255 (End) marque la fin de la liste.
    """
    op     = struct.pack('!B', 2)           # BOOTREPLY
    htype  = struct.pack('!B', 1)           # Ethernet
    hlen   = struct.pack('!B', 6)           # MAC = 6 octets
    hops   = struct.pack('!B', 0)
    xid    = struct.pack('!I', trans_id)    # Même Transaction ID que le DISCOVER
    secs   = struct.pack('!H', 0)
    flags  = struct.pack('!H', 0x8000)      # Broadcast : le client n'a pas encore d'IP

    ciaddr = b'\x00' * 4
    yiaddr = socket.inet_aton(ip_offerte)   # "Your IP" : l'IP qu'on offre
    siaddr = socket.inet_aton(SERVEUR_IP)
    giaddr = b'\x00' * 4

    # chaddr : MAC du client sur 16 octets (les 10 derniers sont du padding à 0)
    chaddr = discover[28:34] + b'\x00' * 10

    sname = b'\x00' * 64
    file_ = b'\x00' * 128

    # Cookie magique obligatoire (RFC 2131 §3) : sans lui, le client ignore le paquet
    magic_cookie = b'\x63\x82\x53\x63'

    options = (
        magic_cookie
        + b'\x35\x01\x02'                                       # Option 53 : DHCP OFFER
        + b'\x01\x04' + socket.inet_aton(MASQUE)                # Option 1  : Subnet Mask
        + b'\x03\x04' + socket.inet_aton(PASSERELLE)            # Option 3  : Router
        + b'\x06\x04' + socket.inet_aton(DNS)                   # Option 6  : DNS
        + b'\x33\x04' + struct.pack('!I', BAIL_DUREE)           # Option 51 : Lease Time
        + b'\x36\x04' + socket.inet_aton(SERVEUR_IP)            # Option 54 : Server ID
        + b'\xff'                                                # Option 255: End
    )

    return (op + htype + hlen + hops + xid + secs + flags
            + ciaddr + yiaddr + siaddr + giaddr
            + chaddr + sname + file_ + options)


def lire_option_53(données: bytes) -> int | None:
    """
    Parse les options DHCP pour trouver l'option 53 (Message Type).
    Les options commencent à l'octet 240 (après le magic cookie à 236).
    Retourne la valeur de l'option 53, ou None si absente.
    """
    if len(données) < 240:
        return None
    i = 240
    while i < len(données):
        opt_type = données[i]
        if opt_type == 255:   # End
            break
        if opt_type == 0:     # Pad : octet ignoré
            i += 1
            continue
        if i + 1 >= len(données):
            break
        opt_len = données[i + 1]
        if opt_type == 53 and opt_len == 1:
            return données[i + 2]
        i += 2 + opt_len
    return None


def main():
    print("=== MINI-SERVEUR DHCP ===")
    print(f"Pool : {POOL_IPS[0]} → {POOL_IPS[-1]}")
    print(f"Masque : {MASQUE}  |  Passerelle : {PASSERELLE}  |  DNS : {DNS}")
    print("Observer : sudo tcpdump -i any udp port 67 or port 68 -n")
    print("Ctrl+C pour arrêter.\n")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', 67))    # Port 67 = serveur DHCP (client = 68)
    except PermissionError:
        print("Droits root requis : sudo python3 bible_code/module_03_services/02_mini_dhcp.py")
        return

    try:
        while True:
            données, adresse = sock.recvfrom(1024)

            if len(données) < 240:
                continue

            trans_id   = struct.unpack('!I', données[4:8])[0]
            mac_client = mac_vers_str(données[28:34])
            msg_type   = lire_option_53(données)

            if msg_type == 1:   # DISCOVER
                ip_offerte = attribuer_ip(mac_client)
                if ip_offerte:
                    print(f"DISCOVER  {mac_client} → OFFER {ip_offerte}")
                    réponse = forger_dhcp_offer(données, ip_offerte, trans_id)
                    sock.sendto(réponse, ('<broadcast>', 68))
                else:
                    print(f"DISCOVER  {mac_client} → POOL ÉPUISÉ (pas d'IP disponible)")
            elif msg_type == 3:
                print(f"REQUEST   {mac_client} → (implémentation REQUEST/ACK non incluse ici)")
            elif msg_type is not None:
                print(f"[TYPE={msg_type}] {mac_client} → ignoré")
    except KeyboardInterrupt:
        print("\nServeur DHCP arrêté.")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
