# Module 1 — Couche Liaison (Ethernet / ARP)

**Prérequis :** Linux, `sudo` obligatoire (raw sockets `AF_PACKET`)

| Fichier | Ce qu'il fait | Commande de test |
|---|---|---|
| `01_sniffer_ethernet.py` | Capture et affiche toutes les trames Ethernet | `sudo python3 01_sniffer_ethernet.py` |
| `02_arp_forge.py` | Forge un ARP Request et écoute la réponse | `sudo python3 02_arp_forge.py` |

## Concepts clés

- `AF_PACKET + SOCK_RAW` : accès direct aux trames, avant tout décodage kernel
- `struct.unpack('! 6s 6s H', ...)` : lire des champs binaires à position fixe
- EtherType `0x0806` = ARP, `0x0800` = IPv4
- ARP Request = broadcast MAC `FF:FF:FF:FF:FF:FF`
- La MAC cible d'un ARP Request = `00:00:00:00:00:00` (inconnue par définition)
