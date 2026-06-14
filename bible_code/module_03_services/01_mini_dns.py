#!/usr/bin/env python3
"""
MODULE 3.1 — Mini-Serveur DNS (RFC 1035)
==========================================
Analogie : le DNS, c'est l'annuaire téléphonique d'Internet.
Tu demandes "monprojet.local" et il répond "192.168.50.10".

Ce script implémente cet annuaire en BINAIRE BRUT, exactement comme
un vrai serveur DNS — pas de bibliothèque externe, juste struct + socket.

Structure d'un message DNS (header = 12 octets) :
  [2] Transaction ID   — corrèle la requête et la réponse
  [2] Flags            — QR(1bit) OPCODE(4) AA TC RD RA Z RCODE(4)
  [2] QDCount          — nombre de questions
  [2] ANCount          — nombre de réponses
  [2] NSCount          — nombre d'enregistrements d'autorité
  [2] ARCount          — nombre d'enregistrements additionnels

Section Question (variable) :
  [N] Nom de domaine   — format labels : 3www6google3com0
  [2] QType            — 1 = A (IPv4)
  [2] QClass           — 1 = IN (Internet)

Section Réponse (variable) :
  [2] Nom              — pointeur de compression 0xC00C (→ offset 12)
  [2] Type             — 1 = A
  [2] Class            — 1 = IN
  [4] TTL
  [2] RDLength         — 4 pour une IPv4
  [4] RData            — l'IP en binaire

Crash Test :
  Terminal 1 : python3 bible_code/module_03_services/01_mini_dns.py
  Terminal 2 : dig @127.0.0.1 -p 5353 monprojet.local
               nslookup -port=5353 api.local 127.0.0.1
               dig @127.0.0.1 -p 5353 inconnu.local   <- doit répondre NXDOMAIN
"""

import socket
import struct

# Notre "zone DNS" locale
ZONES = {
    'monprojet.local.': '192.168.50.10',
    'api.local.':       '192.168.50.11',
    'db.local.':        '192.168.50.12',
    'web.local.':       '192.168.50.13',
}

PORT = 5353   # 5353 = mDNS, évite sudo. Port standard DNS = 53.


def parser_nom(données: bytes, offset: int) -> tuple:
    """
    Décode un nom de domaine au format DNS wire (RFC 1035 §3.1).

    Format labels : <longueur><label>...<longueur><label><0x00>
    Exemple "www.google.com" → b'\x03www\x06google\x03com\x00'

    Gère aussi la compression : si les 2 bits de poids fort sont 1 (0xC0xx),
    les 14 bits restants sont un pointeur vers un autre offset dans le paquet.
    """
    labels = []
    visited = set()   # protection contre les boucles de compression infinies

    while True:
        if offset in visited:
            break
        visited.add(offset)

        longueur = données[offset]

        if longueur == 0:
            offset += 1
            break

        if longueur & 0xC0 == 0xC0:
            # Pointeur de compression : on saute à un autre endroit
            pointeur = struct.unpack('!H', données[offset:offset + 2])[0] & 0x3FFF
            label_suite, _ = parser_nom(données, pointeur)
            labels.append(label_suite.rstrip('.'))
            offset += 2
            break

        offset += 1
        labels.append(données[offset:offset + longueur].decode('utf-8', errors='replace'))
        offset += longueur

    return '.'.join(labels) + '.', offset


def fin_section_question(données: bytes) -> int:
    """
    Retourne l'offset de fin de la première section Question DNS.
    Structure : [nom variable][0x00][QTYPE 2 octets][QCLASS 2 octets]
    On avance octet par octet sur le nom, puis on ajoute 4 pour QTYPE+QCLASS.
    """
    i = 12   # la question commence toujours à l'octet 12
    while i < len(données):
        longueur = données[i]
        if longueur == 0:
            return i + 1 + 4   # 0x00 + QTYPE(2) + QCLASS(2)
        if longueur & 0xC0 == 0xC0:
            return i + 2 + 4   # pointeur 2 octets + QTYPE + QCLASS
        i += 1 + longueur
    return len(données)


def forger_reponse(requête: bytes, ip: str) -> bytes:
    """
    Construit une réponse DNS valide (type A) conforme RFC 1035.
    On réutilise le Transaction ID et la section Question de la requête.

    Note : on copie UNIQUEMENT la section Question (nom + QTYPE + QCLASS),
    pas les enregistrements additionnels (comme l'OPT/EDNS0 de dig).
    Copier l'OPT record dans la réponse rendrait le message malformé.
    """
    trans_id = requête[:2]

    # Flags 0x8400 :
    #   QR=1     (c'est une réponse)
    #   AA=1     (authoritative answer, on fait autorité pour notre zone)
    #   RCODE=0  (pas d'erreur)
    flags    = struct.pack('!H', 0x8400)
    qdcount  = struct.pack('!H', 1)
    ancount  = struct.pack('!H', 1)
    nscount  = struct.pack('!H', 0)
    arcount  = struct.pack('!H', 0)

    # Section Question : seulement les octets du nom + QTYPE + QCLASS
    fin_q = fin_section_question(requête)
    section_question = requête[12:fin_q]

    # Section Réponse
    # 0xC00C = pointeur de compression vers l'offset 12 (début du nom dans la question)
    # Évite de répéter le nom de domaine en entier.
    nom       = struct.pack('!H', 0xC00C)
    type_a    = struct.pack('!H', 1)         # Type A = adresse IPv4
    classe_in = struct.pack('!H', 1)         # Class IN = Internet
    ttl       = struct.pack('!I', 60)        # 60 secondes de cache
    rdlength  = struct.pack('!H', 4)         # IPv4 = 4 octets
    rdata     = socket.inet_aton(ip)         # L'IP convertie en 4 octets

    section_reponse = nom + type_a + classe_in + ttl + rdlength + rdata

    return (trans_id + flags + qdcount + ancount + nscount + arcount
            + section_question + section_reponse)


def forger_nxdomain(requête: bytes) -> bytes:
    """Réponse NXDOMAIN (domaine inexistant) : RCODE = 3."""
    trans_id = requête[:2]
    flags    = struct.pack('!H', 0x8403)   # QR=1, AA=1, RCODE=3
    counts   = struct.pack('!HHHH', 1, 0, 0, 0)
    fin_q    = fin_section_question(requête)
    return trans_id + flags + counts + requête[12:fin_q]


def main():
    print(f"=== MINI-SERVEUR DNS — UDP port {PORT} ===")
    print("Zones enregistrées :")
    for domaine, ip in ZONES.items():
        print(f"  {domaine:<28} → {ip}")
    print(f"\nTest : dig @127.0.0.1 -p {PORT} monprojet.local")
    print("Ctrl+C pour arrêter.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', PORT))

        try:
            while True:
                # 512 octets = taille max d'un message DNS/UDP selon RFC 1035
                données, adresse = sock.recvfrom(512)

                if len(données) < 12:
                    continue

                trans_id, flags, qdcount = struct.unpack('!HHH', données[:6])

                # Bit 15 des flags = QR. Si QR=1, c'est une réponse, on l'ignore.
                if (flags >> 15) & 1:
                    continue

                domaine, _ = parser_nom(données, 12)
                print(f"{adresse[0]}:{adresse[1]}  QUERY  {domaine!r:<32}", end='  ')

                if domaine in ZONES:
                    ip = ZONES[domaine]
                    réponse = forger_reponse(données, ip)
                    print(f"→ {ip}")
                else:
                    réponse = forger_nxdomain(données)
                    print("→ NXDOMAIN")

                sock.sendto(réponse, adresse)
        except KeyboardInterrupt:
            print("\nServeur DNS arrêté.")


if __name__ == '__main__':
    main()
