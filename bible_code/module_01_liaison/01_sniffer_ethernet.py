#!/usr/bin/env python3
"""
MODULE 1.1 — Sniffer Ethernet (Couche 2)
==========================================
Analogie : une carte réseau est comme une oreille collée au mur.
Elle "entend" TOUTES les trames qui passent sur le câble, même celles
qui ne lui sont pas destinées. Ce script colle cette oreille et
décode ce qu'elle entend.

Structure d'une trame Ethernet II :
  [6 octets] MAC destination
  [6 octets] MAC source
  [2 octets] EtherType  (0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6)
  [N octets] Données (le paquet IP, ARP, etc.)

Crash Test :
  sudo python3 bible_code/module_01_liaison/01_sniffer_ethernet.py
  -> puis pingue une machine ou ouvre un navigateur pour générer du trafic
"""

import socket
import struct

ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "802.1Q VLAN",
    0x0835: "RARP",
}


def mac_vers_str(octets):
    """Convertit 6 octets bruts en notation lisible : AA:BB:CC:DD:EE:FF"""
    return ':'.join(f'{b:02X}' for b in octets)


def decoder_ethernet(trame):
    """
    Décode les 14 premiers octets d'une trame Ethernet II.
    struct.unpack :
      '!' = big-endian (ordre réseau)
      '6s' = 6 octets bruts (une adresse MAC)
      'H'  = unsigned short 2 octets (l'EtherType)
    """
    mac_dest_raw, mac_src_raw, ethertype = struct.unpack('! 6s 6s H', trame[:14])
    mac_dest = mac_vers_str(mac_dest_raw)
    mac_src  = mac_vers_str(mac_src_raw)
    nom_type = ETHERTYPES.get(ethertype, f"Inconnu (0x{ethertype:04X})")
    payload  = trame[14:]
    return mac_dest, mac_src, ethertype, nom_type, payload


def main():
    print("=== SNIFFER ETHERNET — Couche 2 ===")
    print("Capture toutes les trames sur toutes les interfaces.")
    print("Ctrl+C pour arrêter.\n")

    # AF_PACKET + SOCK_RAW = accès direct aux trames Ethernet brutes (Linux uniquement)
    # htons(0x0003) = ETH_P_ALL : capturer TOUS les types de trames
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except PermissionError:
        print("Droits root requis. Lancez : sudo python3 bible_code/module_01_liaison/01_sniffer_ethernet.py")
        return

    compteur = 0
    try:
        while True:
            # recvfrom retourne (trame_brute, (interface, ethertype, pkt_type, arphrd, addr))
            trame, meta = sock.recvfrom(65535)
            interface = meta[0]
            mac_dest, mac_src, ethertype, nom_type, payload = decoder_ethernet(trame)

            compteur += 1
            print(
                f"[#{compteur:04d}] {interface:<8} | "
                f"{mac_src} → {mac_dest} | "
                f"{nom_type:<18} | "
                f"{len(payload):4d} octets"
            )
    except KeyboardInterrupt:
        print(f"\n{compteur} trames capturées.")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
