import builtins

# Demande si l'utilisateur veut être l'ordi A ou l'ordi B.
# Nous interceptons temporairement les appels à input() afin de
# pré-remplir les champs correspondants sans modifier le reste du code.
_orig_input = builtins.input
role = _orig_input("Voulez-vous être l'ordi A ou l'ordi B ? (A/B) : ").strip().upper()
if role not in ("A", "B"):
    # Valeur par défaut si entrée invalide
    role = "A"

if role == "A":
    _user_ip = _orig_input("Entrez votre adresse IPv4 (ordi A) : ")
    _user_mac = _orig_input("Entrez votre adresse MAC (ordi A) : ")
else:
    _user_ip = _orig_input("Entrez votre adresse IPv4 (ordi B) : ")
    _user_mac = _orig_input("Entrez votre adresse MAC (ordi B) : ")

def input(prompt: str = "") -> str:
    """Remplace input() pour retourner les valeurs saisies par l'utilisateur
    quand le prompt concerne l'ordi choisi, sinon délègue à l'input original."""
    # On cherche des indices simples dans le prompt pour savoir s'il s'agit
    # de l'ordi A ou B et si c'est une adresse IPv4 ou MAC.
    lower = prompt.lower()
    if "ordi a" in lower and role == "A":
        return _user_ip if "adresse ipv4" in lower or "ipv4" in lower else _user_mac
    if "ordi b" in lower and role == "B":
        return _user_ip if "adresse ipv4" in lower or "ipv4" in lower else _user_mac
    # Sinon, utiliser l'input original
    return _orig_input(prompt)

computer_a_ipv4 = input(f"entrez l'adresse IPv4 de l'ordi A (ex:192.168.1.1) : ")
computer_a_mac_addr = input(f"entrez l'adresse MAC de l'ordi A (ex:00:1A:2B:3C:4D:5E) : ")
computer_b_ipv4 = input(f"entrez l'adresse IPv4 de l'ordi B (ex:192.168.1.2) : ")
computer_b_mac_addr = input(f"entrez l'adresse MAC de l'ordi B (ex:00:1A:2B:3C:4D:5F) : ")

arp_table = {
    computer_a_ipv4: computer_a_mac_addr,
    computer_b_ipv4: computer_b_mac_addr
}
print("Table ARP initiale :", arp_table)

def arp_request(ipv4_address):
    if ipv4_address in arp_table:
        return arp_table[ipv4_address]
    else:
        return "Adresse MAC non trouvée dans la table ARP."
    
requested_ip = input("entrez l'adresse IPv4 à rechercher dans la table ARP : ")
mac_address = arp_request(requested_ip)
print(f"L'adresse MAC pour l'IPv4 {requested_ip} est : {mac_address}")

