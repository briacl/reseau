#!/usr/bin/env python3
"""
ip_subnet_visualizer.py
Programme pédagogique (français) pour expliquer étape par étape le calcul d'un sous-réseau IPv4.
- Conversion décimal -> binaire octet par octet
- Masque de sous-réseau (dotted & /CIDR)
- Opération AND pour obtenir l'adresse réseau
- Calcul de broadcast, plage d'hôtes et nombre d'hôtes
- Détermination de la classe (A..E) et remarques

Usage interactif : lancez le script et indiquez une IP (ex: 192.168.1.10/24 ou 10.0.0.1 255.0.0.0)

Auteur: généré automatiquement (pédagogique)
"""

import sys
import ipaddress


def validate_and_parse(input_str):
    """Accepte :
      - '192.168.1.10/24'
      - '192.168.1.10 255.255.255.0'
      - '192.168.1.10' (demande ensuite le masque)
    Retour: (ip_str, cidr_int)
    """
    s = input_str.strip()
    if '/' in s:
        try:
            ip_part, cidr_part = s.split('/')
            ipaddress.IPv4Address(ip_part)
            cidr = int(cidr_part)
            if not (0 <= cidr <= 32):
                raise ValueError('CIDR hors plage')
            return ip_part, cidr
        except Exception as e:
            raise ValueError(f"Format invalide (x.x.x.x/yy attendu): {e}")
    # split by whitespace
    parts = s.split()
    if len(parts) == 2:
        ip_part, mask_part = parts
        try:
            ipaddress.IPv4Address(ip_part)
        except Exception:
            raise ValueError('Adresse IP invalide')
        # si mask_part est en dotted
        try:
            mask_octets = [int(x) for x in mask_part.split('.')]
            if len(mask_octets) != 4:
                raise ValueError()
            for o in mask_octets:
                if not (0 <= o <= 255):
                    raise ValueError()
            # convertir mask dotted en CIDR
            mask_int = 0
            for o in mask_octets:
                mask_int = (mask_int << 8) | o
            cidr = mask_int.bit_count()
            return ip_part, cidr
        except Exception:
            raise ValueError('Masque invalide (attendu dotted decimal)')
    # single IP given -> caller should ask for mask
    try:
        ipaddress.IPv4Address(s)
        return s, None
    except Exception:
        raise ValueError('Entrée non reconnue')


def cidr_to_mask(cidr):
    mask_int = ((1 << 32) - 1) ^ ((1 << (32 - cidr)) - 1) if cidr > 0 else 0
    octets = [str((mask_int >> (8 * i)) & 0xFF) for i in reversed(range(4))]
    return '.'.join(octets), mask_int


def ip_to_int(ip_str):
    parts = [int(p) for p in ip_str.split('.')]
    val = 0
    for p in parts:
        val = (val << 8) | p
    return val


def int_to_ip(i):
    return '.'.join(str((i >> (8 * j)) & 0xFF) for j in reversed(range(4)))


def bin_octets_from_int(i):
    return [format((i >> (8 * j)) & 0xFF, '08b') for j in reversed(range(4))]


def pretty_line_decimal_and_binary(decimal_octets, binary_octets):
    # return two aligned strings for printing
    dec = '  '.join(f"{o:>3}" for o in decimal_octets)
    bin_ = '  '.join(binary_octets)
    return dec, bin_


def determine_class(first_octet):
    # Returns (class_letter, explanation)
    fo = first_octet
    if 1 <= fo <= 126:
        return 'A', 'Classe A: adresse réseau initiale pour très grands réseaux (0 et 127 réservées; 127 = loopback)'
    if 127 == fo:
        return 'loopback', '127.x.x.x: adresse de loopback (réservée pour la machine locale)'
    if 128 <= fo <= 191:
        return 'B', 'Classe B: réseaux de taille moyenne'
    if 192 <= fo <= 223:
        return 'C', 'Classe C: petits réseaux (souvent utilisés pour LAN)'
    if 224 <= fo <= 239:
        return 'D', 'Classe D: adresses multicast'
    if 240 <= fo <= 255:
        return 'E', "Classe E: réservée / expérimentale"
    return 'Unknown', ''


def format_table(headers, rows, sep=' | '):
    """Retourne une chaîne représentant un tableau ASCII simple.
    headers: liste de titres de colonnes
    rows: liste de listes (valeurs par colonne)
    """
    # calculer largeur par colonne
    cols = len(headers)
    widths = [len(str(h)) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(r[i])))

    def pad(s, w):
        return str(s) + ' ' * (w - len(str(s)))

    # ligne header
    header_line = sep.join(pad(headers[i], widths[i]) for i in range(cols))
    sep_line = '-+-'.join('-' * widths[i] for i in range(cols))
    row_lines = []
    for r in rows:
        row_lines.append(sep.join(pad(r[i], widths[i]) for i in range(cols)))

    return '\n'.join([header_line, sep_line] + row_lines)


def calculate_all(ip_str, cidr):
    ip_i = ip_to_int(ip_str)
    mask_str, mask_i = cidr_to_mask(cidr)
    network_i = ip_i & mask_i
    broadcast_i = network_i | (~mask_i & 0xFFFFFFFF)
    host_part_i = ip_i & (~mask_i & 0xFFFFFFFF)
    host_bits = 32 - cidr
    if host_bits == 0:
        num_hosts = 1  # uniquement l'adresse unique
    elif host_bits == 1:
        num_hosts = 2  # /31 : généralement point-à-point
    else:
        num_hosts = max(0, (2 ** host_bits) - 2)
    return {
        'ip_i': ip_i,
        'mask_str': mask_str,
        'mask_i': mask_i,
        'network_i': network_i,
        'broadcast_i': broadcast_i,
        'host_part_i': host_part_i,
        'host_bits': host_bits,
        'num_hosts': num_hosts,
    }


def show_step_by_step(ip_str, cidr):
    data = calculate_all(ip_str, cidr)
    ip_i = data['ip_i']
    mask_i = data['mask_i']
    network_i = data['network_i']
    broadcast_i = data['broadcast_i']
    host_part_i = data['host_part_i']
    host_bits = data['host_bits']

    ip_octets = [int(x) for x in ip_str.split('.')]
    mask_octets = [int(x) for x in data['mask_str'].split('.')]
    net_octets = [int(x) for x in int_to_ip(network_i).split('.')]
    bc_octets = [int(x) for x in int_to_ip(broadcast_i).split('.')]

    ip_bins = bin_octets_from_int(ip_i)
    mask_bins = bin_octets_from_int(mask_i)
    net_bins = bin_octets_from_int(network_i)
    bc_bins = bin_octets_from_int(broadcast_i)
    host_bins = bin_octets_from_int(host_part_i)

    # Entrée: tableau octet par octet
    print('\n=== Entrée ===')
    headers = ['Type', 'Octet 1', 'Octet 2', 'Octet 3', 'Octet 4']
    rows = [ ['Décimal'] + [str(o) for o in ip_octets], ['Binaire'] + ip_bins ]
    print(format_table(headers, rows))

    # Masque
    print('\n=== Masque ===')
    rows = [ ['Décimal'] + [str(o) for o in mask_octets], ['Binaire'] + mask_bins, ['Info', f"{data['mask_str']} /{cidr}", '', '', ''] ]
    print(format_table(headers, rows))

    # Opération AND - disposition demandée: octets en colonnes horizontales, champs en lignes
    print('\n=== Opération AND (IP AND Masque) — affichage horizontal des octets ===')
    and_headers = ['Champ', 'Octet 1', 'Octet 2', 'Octet 3', 'Octet 4']
    and_rows = []
    and_rows.append(['IP (dec)'] + [str(o) for o in ip_octets])
    and_rows.append(['IP (bin)'] + ip_bins)
    and_rows.append(['Mask (dec)'] + [str(o) for o in mask_octets])
    and_rows.append(['Mask (bin)'] + mask_bins)
    and_dec = [str(a & m) for a, m in zip(ip_octets, mask_octets)]
    and_bin = [format(a & m, '08b') for a, m in zip(ip_octets, mask_octets)]
    and_rows.append(['AND (dec)'] + and_dec)
    and_rows.append(['AND (bin)'] + and_bin)
    print(format_table(and_headers, and_rows))

    # Réseau et broadcast
    print('\n=== Réseau et Broadcast ===')
    nb_headers = ['Item', 'Décimal', 'Binaire']
    nb_rows = [ ['Réseau', int_to_ip(network_i), ' '.join(net_bins)],
                ['Broadcast', int_to_ip(broadcast_i), ' '.join(bc_bins)],
                ['Partie hôte (binaire)', str(host_part_i), ' '.join(host_bins)] ]
    print(format_table(nb_headers, nb_rows))

    # Plage d'hôtes
    print('\n=== Plage d\'hôtes ===')
    if host_bits == 0:
        print('Pas de bits hôte (/32): adresse unique, pas de plage d\'hôtes.')
        host_table = [['Type', 'Valeur'], ['Hôtes utilisables', 'aucun (adresse unique)']]
    elif host_bits == 1:
        print('/31 : utilisé pour point-à-point (2 adresses).')
        host_table = [['Type', 'Valeur'], ['Hôtes utilisables', 'spécial (/31)']] 
    else:
        first_host = network_i + 1
        last_host = broadcast_i - 1
        host_table = [['Type', 'Valeur'], ['Plage', f"{int_to_ip(first_host)} - {int_to_ip(last_host)}"], ['Nombre hôtes', str(data['num_hosts'])]]
    print(format_table(['Champ', 'Valeur'], host_table[1:]))

    # Classe
    classe, explanation = determine_class(ip_octets[0])
    print('\n=== Classe de l\'adresse ===')
    print(format_table(['Champ', 'Valeur'], [['Adresse', ip_str], ['Classe', classe], ['Remarque', explanation]]))

    # Résumé compact
    print('\n=== Résumé compact ===')
    summary_rows = [ ['IP', ip_str], ['Masque', f"{data['mask_str']} /{cidr}"], ['Réseau', int_to_ip(network_i)], ['Broadcast', int_to_ip(broadcast_i)] ]
    if host_bits >= 2:
        summary_rows.append(['Hôtes utilisables', f"{int_to_ip(network_i+1)} - {int_to_ip(broadcast_i-1)} ({data['num_hosts']} hôtes)"])
    else:
        summary_rows.append(['Hôtes utilisables', 'spécial (/31 ou /32)'])
    print(format_table(['Champ', 'Valeur'], summary_rows))


def interactive():
    print('Visualiseur pédagogique d\'adresse IPv4 et sous-réseau (français)')
    print('Entrez une adresse IPv4 avec /CIDR (ex: 192.168.1.10/24) ou IP puis masque (ex: 10.0.0.1 255.0.0.0).')
    print("Tapez 'exemple' pour voir des exemples prédéfinis ou 'q' pour quitter.")

    while True:
        try:
            s = input('\n> ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\nQuit.')
            return
        if not s:
            continue
        if s.lower() in ('q', 'quit', 'exit'):
            print('Au revoir.')
            return
        if s.lower() == 'exemple':
            examples = [
                '192.168.1.10/24',
                '10.1.2.3/8',
                '172.16.5.4 255.255.0.0',
                '192.0.2.5/29',
                '203.0.113.7/32',
            ]
            for e in examples:
                print('\n--- Exemple:', e, '---')
                ip, cidr = validate_and_parse(e)
                show_step_by_step(ip, cidr)
            continue
        try:
            ip, cidr = validate_and_parse(s)
            if cidr is None:
                # demander cidr
                while True:
                    m = input('Masque (ex 255.255.255.0 ou /24) : ').strip()
                    if m.startswith('/'):
                        try:
                            c = int(m[1:])
                            if 0 <= c <= 32:
                                cidr = c
                                break
                        except Exception:
                            pass
                        print('CIDR invalide')
                    else:
                        try:
                            # parse dotted
                            mask_octets = [int(x) for x in m.split('.')]
                            mask_int = 0
                            for o in mask_octets:
                                mask_int = (mask_int<<8) | o
                            cidr = mask_int.bit_count()
                            break
                        except Exception:
                            print('Masque invalide, réessayez')
            show_step_by_step(ip, cidr)
        except ValueError as e:
            print('Erreur:', e)


def quick_demo_from_args():
    # si appel: python ip_subnet_visualizer.py 192.168.1.10/24
    if len(sys.argv) > 1:
        input_arg = ' '.join(sys.argv[1:])
        ip, cidr = validate_and_parse(input_arg)
        if cidr is None:
            raise SystemExit('Fournissez le masque si vous utilisez des arguments.')
        show_step_by_step(ip, cidr)
        return True
    return False


if __name__ == '__main__':
    try:
        ran = quick_demo_from_args()
        if not ran:
            interactive()
    except Exception as e:
        print('Erreur fatale:', e)
        sys.exit(1)
