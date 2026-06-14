#!/usr/bin/env python3
"""
MODULE 1.3 — Encapsulateur de Message (Simulation)
====================================================
Ce script prend un texte et le transforme en une vraie trame réseau binaire,
exactement comme le ferait votre carte réseau — sans rien envoyer sur le réseau.

Objectif pédagogique :
  Visualiser que "Hello" et "n'importe quelle page web" ne sont que des octets,
  empilés dans un ordre très précis, délimités par des séries fixes de 0 et 1.
  C'est exactement ce que Wireshark vous montre dans ses captures.

Structure construite (de bas en haut) :
  ┌───────────────────────────────────────────┐
  │  ETHERNET  (14 octets)  ← Couche 2        │
  │  ┌───────────────────────────────────────┐│
  │  │  IP  (20 octets)  ← Couche 3          ││
  │  │  ┌─────────────────────────────────┐  ││
  │  │  │  UDP  (8 octets)  ← Couche 4    │  ││
  │  │  │  ┌───────────────────────────┐  │  ││
  │  │  │  │  DONNÉES (votre texte)    │  │  ││
  │  │  │  └───────────────────────────┘  │  ││
  │  │  └─────────────────────────────────┘  ││
  │  └───────────────────────────────────────┘│
  └───────────────────────────────────────────┘

Crash Test :
  python3 bible_code/module_01_liaison/03_encapsulateur.py
"""

import struct
import socket

# ── Couleurs terminal ─────────────────────────────────────────────────────────
R  = '\033[91m'   # rouge   → Ethernet
J  = '\033[93m'   # jaune   → IP
V  = '\033[92m'   # vert    → UDP
C  = '\033[96m'   # cyan    → Données
G  = '\033[90m'   # gris    → annotation
B  = '\033[1m'    # gras
N  = '\033[0m'    # reset


# ── Utilitaires ───────────────────────────────────────────────────────────────

def mac_str_vers_bytes(mac: str) -> bytes:
    """'AA:BB:CC:DD:EE:FF' → b'\xaa\xbb\xcc\xdd\xee\xff'"""
    return bytes(int(x, 16) for x in mac.split(':'))


def bytes_vers_hex(données: bytes, sep: str = ' ') -> str:
    return sep.join(f'{b:02X}' for b in données)


def bytes_vers_bin(données: bytes, sep: str = ' ') -> str:
    return sep.join(f'{b:08b}' for b in données)


def checksum_ip(header: bytes) -> int:
    """
    Calcul du checksum IP (RFC 791) :
    Somme de tous les mots de 16 bits, puis complément à 1.
    Le checksum est inclus dans le header avec la valeur 0 pour le calcul.
    """
    if len(header) % 2:
        header += b'\x00'
    total = 0
    for i in range(0, len(header), 2):
        mot = (header[i] << 8) + header[i + 1]
        total += mot
    # Ramener sur 16 bits en ajoutant les retenues
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def checksum_udp(src_ip: str, dst_ip: str, udp_segment: bytes) -> int:
    """
    Checksum UDP calculé sur un pseudo-header IP + segment UDP.
    Le pseudo-header garantit que les données arrivent à la bonne destination.
    """
    pseudo = (
        socket.inet_aton(src_ip) +
        socket.inet_aton(dst_ip) +
        struct.pack('!BBH', 0, 17, len(udp_segment))
    )
    données = pseudo + udp_segment
    if len(données) % 2:
        données += b'\x00'
    total = 0
    for i in range(0, len(données), 2):
        total += (données[i] << 8) + données[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    résultat = ~total & 0xFFFF
    return résultat if résultat != 0 else 0xFFFF


# ── Construction des couches ──────────────────────────────────────────────────

def construire_udp(src_port: int, dst_port: int, payload: bytes,
                   src_ip: str, dst_ip: str) -> bytes:
    """
    En-tête UDP (8 octets) :
      [2] Port source     [2] Port destination
      [2] Longueur totale [2] Checksum
    """
    longueur = 8 + len(payload)
    # Checksum calculé avec checksum à 0 d'abord
    segment_sans_checksum = struct.pack('!HHHH', src_port, dst_port, longueur, 0) + payload
    cs = checksum_udp(src_ip, dst_ip, segment_sans_checksum)
    return struct.pack('!HHHH', src_port, dst_port, longueur, cs) + payload


def construire_ip(src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    """
    En-tête IPv4 (20 octets) :
      [1] Version+IHL  [1] TOS        [2] Longueur totale
      [2] Identifiant  [2] Flags+Frag [1] TTL  [1] Proto  [2] Checksum
      [4] IP source    [4] IP destination
    """
    version_ihl = (4 << 4) | 5    # version=4, IHL=5 (5×4=20 octets)
    tos         = 0
    longueur    = 20 + len(payload)
    identifiant = 0x1234           # valeur arbitraire pour cet exemple
    flags_frag  = 0                # pas de fragmentation
    ttl         = 64               # valeur standard Linux
    protocole   = 17               # 17 = UDP
    checksum    = 0                # mis à 0 pour le calcul

    header = struct.pack(
        '! B B H H H B B H 4s 4s',
        version_ihl, tos, longueur, identifiant, flags_frag,
        ttl, protocole, checksum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )
    cs = checksum_ip(header)
    # Réinjecter le vrai checksum (octets 10-11)
    return header[:10] + struct.pack('!H', cs) + header[12:] + payload


def construire_ethernet(src_mac: str, dst_mac: str, payload: bytes) -> bytes:
    """
    En-tête Ethernet II (14 octets) :
      [6] MAC destination  [6] MAC source  [2] EtherType
    """
    return (
        mac_str_vers_bytes(dst_mac) +
        mac_str_vers_bytes(src_mac) +
        struct.pack('!H', 0x0800) +   # 0x0800 = IPv4
        payload
    )


# ── Affichage pédagogique ─────────────────────────────────────────────────────

def afficher_couche(nom: str, données: bytes, couleur: str, descriptions: list) -> None:
    """Affiche une couche : hex, binaire, et description champ par champ."""
    print(f"\n{couleur}{B}{'─'*60}")
    print(f"  {nom}  ({len(données)} octets)")
    print(f"{'─'*60}{N}")

    # Hex sur 16 colonnes
    print(f"{couleur}Hexadécimal :{N}")
    for i in range(0, len(données), 16):
        bloc = données[i:i+16]
        print(f"  {G}{i:04X}{N}  {couleur}{bytes_vers_hex(bloc):<47}{N}")

    # Binaire sur 4 colonnes (4 octets par ligne = 32 bits, comme les schémas RFC)
    print(f"\n{couleur}Binaire (chaque groupe = 1 octet = 8 bits) :{N}")
    for i in range(0, len(données), 4):
        bloc = données[i:i+4]
        print(f"  {couleur}{bytes_vers_bin(bloc)}{N}")

    # Description des champs
    if descriptions:
        print(f"\n{couleur}Décodage des champs :{N}")
        for ligne in descriptions:
            print(f"  {ligne}")


def hexdump_wireshark(trame: bytes) -> None:
    """
    Affiche la trame complète au format Wireshark (hexdump classique) :
    offset  16 octets en hex  représentation ASCII
    """
    print(f"\n{B}{'═'*70}")
    print("  VUE WIRESHARK — Trame complète")
    print(f"{'═'*70}{N}")
    print(f"{G}         00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII{N}")
    print(f"{G}{'─'*70}{N}")

    for i in range(0, len(trame), 16):
        bloc = trame[i:i+16]
        hex_partie = ' '.join(f'{b:02X}' for b in bloc[:8])
        hex_partie2 = ' '.join(f'{b:02X}' for b in bloc[8:])
        ascii_partie = ''.join(chr(b) if 32 <= b < 127 else '.' for b in bloc)
        print(f"  {G}{i:04X}{N}  {hex_partie:<23}  {hex_partie2:<23}   {ascii_partie}")


def flux_binaire_complet(trame: bytes) -> None:
    """Affiche les N premiers octets en binaire pur, comme un signal électrique."""
    print(f"\n{B}{'═'*70}")
    print("  FLUX BINAIRE — Ce que voit la carte réseau (premiers 56 octets)")
    print(f"{'═'*70}{N}")
    print(f"{G}  (chaque groupe de 8 = 1 octet, chaque bit = un signal électrique){N}\n")

    extrait = trame[:56]
    couleurs_couches = [R]*14 + [J]*20 + [V]*8 + [C]*14
    couleurs_couches = couleurs_couches[:len(extrait)]

    ligne = ''
    for i, (octet, coul) in enumerate(zip(extrait, couleurs_couches)):
        ligne += f"{coul}{octet:08b}{N} "
        if (i + 1) % 4 == 0:
            print(f"  {ligne}")
            ligne = ''
    if ligne:
        print(f"  {ligne}")

    if len(trame) > 56:
        print(f"\n  {G}... + {len(trame) - 56} octets supplémentaires (données){N}")


def legende() -> None:
    print(f"\n  Légende des couleurs :")
    print(f"  {R}██{N} Ethernet (Couche 2)  "
          f"{J}██{N} IP (Couche 3)  "
          f"{V}██{N} UDP (Couche 4)  "
          f"{C}██{N} Données")


# ── Programme principal ───────────────────────────────────────────────────────

def main():
    print(f"\n{B}=== ENCAPSULATEUR DE MESSAGE — Visualisation binaire ==={N}")
    print("Construit une vraie trame réseau et montre chaque octet.\n")

    # Saisie utilisateur
    message   = input("Message à encapsuler : ").strip()
    if not message:
        message = "Hello, réseau !"

    src_ip    = input("IP source      (Entrée = 192.168.1.10) : ").strip() or "192.168.1.10"
    dst_ip    = input("IP destination (Entrée = 192.168.1.1)  : ").strip() or "192.168.1.1"
    src_mac   = input("MAC source     (Entrée = AA:BB:CC:DD:EE:11) : ").strip() or "AA:BB:CC:DD:EE:11"
    dst_mac   = input("MAC destination(Entrée = AA:BB:CC:DD:EE:22) : ").strip() or "AA:BB:CC:DD:EE:22"
    src_port  = 12345
    dst_port  = 80

    payload   = message.encode('utf-8')

    # ── Étape 0 : le message brut ──────────────────────────────────────────────
    print(f"\n{B}{'═'*70}")
    print("  ÉTAPE 0 — Le message texte, tel qu'il existe dans la mémoire")
    print(f"{'═'*70}{N}")
    print(f"\n  Texte    : {C}{message}{N}")
    print(f"  ASCII/UTF-8  → chaque caractère a un code numérique :")
    for car in message[:20]:
        print(f"    '{car}'  →  décimal {ord(car):3d}  →  hex {ord(car):02X}  →  binaire {ord(car):08b}")
    if len(message) > 20:
        print(f"    ... ({len(message) - 20} caractères supplémentaires)")

    # ── Construction des couches ───────────────────────────────────────────────
    segment_udp = construire_udp(src_port, dst_port, payload, src_ip, dst_ip)
    paquet_ip   = construire_ip(src_ip, dst_ip, segment_udp)
    trame       = construire_ethernet(src_mac, dst_mac, paquet_ip)

    # Découpage pour l'affichage
    eth_header  = trame[:14]
    ip_header   = trame[14:34]
    udp_header  = trame[34:42]
    données_raw = trame[42:]

    # ── Affichage couche par couche ────────────────────────────────────────────

    # Décoder les valeurs IP pour la description
    ip_cs = struct.unpack('!H', ip_header[10:12])[0]
    udp_cs = struct.unpack('!H', udp_header[6:8])[0]

    afficher_couche(
        "COUCHE 2 — En-tête ETHERNET II", eth_header, R,
        [
            f"{R}[00-05]{N} MAC destination : {bytes_vers_hex(eth_header[0:6])}  → {dst_mac}",
            f"{R}[06-11]{N} MAC source      : {bytes_vers_hex(eth_header[6:12])} → {src_mac}",
            f"{R}[12-13]{N} EtherType       : {bytes_vers_hex(eth_header[12:14])}        → 0x0800 = IPv4",
        ]
    )

    afficher_couche(
        "COUCHE 3 — En-tête IPv4", ip_header, J,
        [
            f"{J}[00]   {N} Version + IHL   : {ip_header[0]:08b} → v4, header=20 oct",
            f"{J}[01]   {N} TOS             : {ip_header[1]:08b} → priorité normale",
            f"{J}[02-03]{N} Longueur totale : {struct.unpack('!H', ip_header[2:4])[0]} octets",
            f"{J}[04-05]{N} Identifiant     : 0x{struct.unpack('!H', ip_header[4:6])[0]:04X}",
            f"{J}[06-07]{N} Flags + Frag    : {struct.unpack('!H', ip_header[6:8])[0]} (pas de fragmentation)",
            f"{J}[08]   {N} TTL             : {ip_header[8]} (décrémenté à chaque routeur)",
            f"{J}[09]   {N} Protocole       : {ip_header[9]} → 17 = UDP",
            f"{J}[10-11]{N} Checksum        : 0x{ip_cs:04X} (vérifie l'intégrité du header)",
            f"{J}[12-15]{N} IP source       : {bytes_vers_hex(ip_header[12:16])} → {src_ip}",
            f"{J}[16-19]{N} IP destination  : {bytes_vers_hex(ip_header[16:20])} → {dst_ip}",
        ]
    )

    afficher_couche(
        "COUCHE 4 — En-tête UDP", udp_header, V,
        [
            f"{V}[00-01]{N} Port source     : {src_port}  (port éphémère du client)",
            f"{V}[02-03]{N} Port destination: {dst_port}   (port 80 = HTTP)",
            f"{V}[04-05]{N} Longueur        : {struct.unpack('!H', udp_header[4:6])[0]} octets (header + données)",
            f"{V}[06-07]{N} Checksum UDP    : 0x{udp_cs:04X}",
        ]
    )

    afficher_couche(
        "DONNÉES — Payload (votre message)", données_raw, C,
        [f"{C}  {bytes_vers_hex(données_raw)}{N}",
         f"  → \"{données_raw.decode('utf-8', errors='replace')}\""]
    )

    # ── Vue Wireshark ──────────────────────────────────────────────────────────
    hexdump_wireshark(trame)

    # ── Flux binaire ───────────────────────────────────────────────────────────
    flux_binaire_complet(trame)
    legende()

    # ── Statistiques ──────────────────────────────────────────────────────────
    print(f"\n{B}{'═'*70}")
    print("  BILAN")
    print(f"{'═'*70}{N}")
    print(f"  Message original  : {len(payload)} octets  ({len(payload)*8} bits)")
    print(f"  En-têtes ajoutés  : {14+20+8} octets  ({(14+20+8)*8} bits)")
    print(f"  Trame totale      : {len(trame)} octets  ({len(trame)*8} bits)")
    surcoût = (14+20+8) / len(trame) * 100
    print(f"  Surcoût protocolaire : {surcoût:.1f}% de la trame = en-têtes, 0 = message")
    print(f"\n  → Sur le câble, votre texte de {len(payload)} octet(s) devient")
    print(f"    une séquence de {len(trame)*8} impulsions électriques.")
    print()


if __name__ == '__main__':
    main()
