#!/usr/bin/env python3
"""
Programme pédagogique (français) : simule étape par étape l'envoi d'un message
depuis la machine A vers la machine B, en encapsulant le message dans une
trame Ethernet et en le transmettant via un switch simple (apprentissage
MAC + forwarding / flooding).

But: ce script est une simulation pédagogique, il n'émet pas de trames réelles.
"""

import time
import textwrap
import shutil

SLEEP = 0.6  # délai visuel entre étapes (réduit si vous voulez plus rapide)


def slow_print(text, delay=SLEEP):
	print(text)
	time.sleep(delay)


def _col_widths(headers, rows):
	widths = [len(h) for h in headers]
	for r in rows:
		for i, c in enumerate(r):
			widths[i] = max(widths[i], len(str(c)))
	return widths


def print_table(title, headers, rows):
	"""Affiche un tableau ascii simple avec un titre."""
	print(title)
	if not headers:
		return
	widths = _col_widths(headers, rows)
	line = "+" + "+".join('-' * (w + 2) for w in widths) + "+"
	# header
	print(line)
	hdr = "|" + "|".join(f" {h.ljust(widths[i])} " for i, h in enumerate(headers)) + "|"
	print(hdr)
	print(line)
	for r in rows:
		row_s = "|" + "|".join(f" {str(c).ljust(widths[i])} " for i, c in enumerate(r)) + "|"
		print(row_s)
	print(line)


def print_kv_table(title, d, key_name='Key', val_name='Value'):
	headers = [key_name, val_name]
	rows = []
	for k in sorted(d.keys(), key=lambda x: str(x)):
		rows.append([k, d[k]])
	print_table(title, headers, rows)


def fmt_frame(dst_mac, src_mac, ethertype, payload):
	hdr = f"DST={dst_mac} | SRC={src_mac} | TYPE=0x{ethertype:04X}"
	body = textwrap.indent(payload, '    ')
	return f"{hdr}\n{body}"


def simulate():
	slow_print("--- Simulation pédagogique: envoi d'un message A -> B via switch ---\n")

	# Entrées utilisateur pour 5 machines (A..E)
	a_ip = input("Entrez l'adresse IPv4 de l'ordi A (ex: 192.168.10.1) : ").strip()
	a_mac = input("Entrez l'adresse MAC de l'ordi A (ex: 00:1A:2B:3C:4D:5E) : ").strip()
	b_ip = input("Entrez l'adresse IPv4 de l'ordi B (ex: 192.168.10.2) : ").strip()
	b_mac = input("Entrez l'adresse MAC de l'ordi B (ex: 00:1A:2B:3C:4D:5F) : ").strip()
	c_ip = input("Entrez l'adresse IPv4 de l'ordi C (ex: 192.168.10.3) : ").strip()
	c_mac = input("Entrez l'adresse MAC de l'ordi C (ex: 00:1A:2B:3C:4D:60) : ").strip()
	d_ip = input("Entrez l'adresse IPv4 de l'ordi D (ex: 192.168.10.4) : ").strip()
	d_mac = input("Entrez l'adresse MAC de l'ordi D (ex: 00:1A:2B:3C:4D:61) : ").strip()
	e_ip = input("Entrez l'adresse IPv4 de l'ordi E (ex: 192.168.10.5) : ").strip()
	e_mac = input("Entrez l'adresse MAC de l'ordi E (ex: 00:1A:2B:3C:4D:62) : ").strip()
	message = input("Entrez le message (payload) que A envoie à B : ").strip()

	slow_print("\n1) État initial: table ARP et table MAC du switch vides (simulation)")
	arp_table = {
		a_ip: a_mac,
		b_ip: b_mac,
		c_ip: c_mac,
		d_ip: d_mac,
		e_ip: e_mac,
	}  # on suppose ARP résolu pour pédagogie
	print_kv_table("   Table ARP (simulée)", arp_table, key_name='IP', val_name='MAC')
	mac_table = {}  # switch learning table: MAC -> port
	print_kv_table("   Table MAC du switch (initialement vide)", mac_table, key_name='MAC', val_name='Port')

	# Ports physiques du switch pour chaque machine (simulation)
	ports = {
		a_mac: 'port-1',
		b_mac: 'port-2',
		c_mac: 'port-3',
		d_mac: 'port-4',
		e_mac: 'port-5',
	}
	print_table("   Topologie (MAC -> port)", ["MAC", "Port"], [[k, v] for k, v in ports.items()])

	# Étape ARP (pédagogique): A veut envoyer à B -> trouve MAC via ARP
	slow_print("2) Sur l'ordinateur A :")
	slow_print(f"   A ({a_ip}) veut envoyer un message à B ({b_ip}).")
	if b_ip in arp_table:
		resolved_mac = arp_table[b_ip]
		print_table("   Résolution ARP", ["IP", "MAC"], [[b_ip, resolved_mac]])
	else:
		slow_print("   ARP: pas d'entrée, A envoie une requête ARP et obtient la réponse (simulée).")
		resolved_mac = input("   (Simulation) Entrez la MAC de B obtenue via ARP : ").strip()
		arp_table[b_ip] = resolved_mac
		print_kv_table("   Table ARP mise à jour", arp_table, key_name='IP', val_name='MAC')

	slow_print("\n3) Encapsulation : on encapsule le message dans un paquet IP puis dans une trame Ethernet")
	# Paquet IP simplifié
	ip_packet = f"IP(src={a_ip}, dst={b_ip}, payload='{message}')"
	print_table("   Paquet IP construit", ["Champ", "Valeur"], [["src", a_ip], ["dst", b_ip], ["payload", message]])

	# Trame Ethernet simplifiée
	ethertype_ipv4 = 0x0800
	ethernet_frame = fmt_frame(dst_mac=resolved_mac, src_mac=a_mac, ethertype=ethertype_ipv4, payload=ip_packet)
	# Afficher la trame sous forme de tableau (champs Ethernet + payload résumé)
	print_table("   Trame Ethernet construite", ["Champ", "Valeur"], [["DST", resolved_mac], ["SRC", a_mac], ["Type", f"0x{ethertype_ipv4:04X}"], ["Payload", ip_packet]])
	time.sleep(SLEEP)

	slow_print("\n4) Envoi de la trame vers le switch (le switch reçoit la trame sur le port relié à A)")
	incoming_port = ports[a_mac]  # A connecté au port-1 du switch
	slow_print(f"   Le switch reçoit une trame sur {incoming_port}. Il va apprendre l'adresse source et consulter sa table MAC." )

	# Switch learning: associer SRC MAC au port d'arrivée
	mac_table[a_mac] = incoming_port
	print_table("   Le switch apprend (mise à jour)", ["MAC", "Port"], [[a_mac, incoming_port]])

	# Forwarding decision: si DST MAC connu -> envoyer sur le port connu; sinon flood
	slow_print(f"   Le switch cherche la MAC de destination {resolved_mac} dans sa table...")
	if resolved_mac in mac_table:
		out_ports = [mac_table[resolved_mac]]
		print_table("   Décision de forwarding", ["DST MAC", "Connue", "Out port(s)"], [[resolved_mac, "Oui", out_ports[0]]])
	else:
		# Flood: envoyer sur tous les ports sauf celui d'entrée
		out_ports = [p for m, p in ports.items() if p != incoming_port]
		print_table("   Décision de forwarding (flood)", ["DST MAC", "Connue", "Out ports"], [[resolved_mac, "Non", ", ".join(out_ports)]])

	time.sleep(SLEEP)
	# Vérifier si B est dans les ports destinataires
	slow_print(f"\n5) Arrivée sur {out_ports} -> l'ordinateur(s) connecté(s) sur ces ports reçoivent la trame")
	slow_print("   Chaque machine destinataire vérifie la trame: si la DST MAC lui correspond, elle dépile l'Ethernet, puis l'IP, et lit le message.")

	mac_name = {a_mac: 'A', b_mac: 'B', c_mac: 'C', d_mac: 'D', e_mac: 'E'}
	rows = []
	for mac, port in ports.items():
		host = mac_name.get(mac, mac)
		received = 'Oui' if port in out_ports else 'Non'
		rows.append([port, host, received])
	print_table("   Sorties du switch et réception", ["Port", "Machine", "Reçu?"], rows)

	# Vérification spécifique pour B
	if ports[b_mac] in out_ports:
		print_table("   Réception par B", ["Hôte", "IP", "Message"], [["B", b_ip, message]])
	else:
		print_table("   Réception par B", ["Hôte", "IP", "Message"], [["B", b_ip, "(n'a pas reçu)"]])

	# Optionnel: B apprend aussi l'adresse source en répondant, switch mettra à jour
	slow_print("\n6) Apprentissage réciproque (optionnel): B peut répondre et le switch apprendra la MAC de B")
	mac_table[b_mac] = 'port-2'
	print_kv_table("   Table MAC du switch finale", mac_table, key_name='MAC', val_name='Port')

	slow_print("\n--- Fin de la simulation ---")


if __name__ == '__main__':
	simulate()


