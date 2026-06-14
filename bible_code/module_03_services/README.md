# Module 3 — Services Réseau (DNS / DHCP)

| Fichier | Port | Sudo ? | Commande de test |
|---|---|---|---|
| `01_mini_dns.py` | UDP 5353 | Non | `dig @127.0.0.1 -p 5353 monprojet.local` |
| `02_mini_dhcp.py` | UDP 67/68 | Oui | VM + `sudo dhclient -v eth0` |

## DNS — Test complet

```bash
# Lancer le serveur
python3 01_mini_dns.py

# Requêtes de test (autre terminal)
dig @127.0.0.1 -p 5353 monprojet.local     # doit répondre 192.168.50.10
dig @127.0.0.1 -p 5353 api.local            # doit répondre 192.168.50.11
dig @127.0.0.1 -p 5353 inconnu.local        # doit répondre NXDOMAIN
nslookup -port=5353 db.local 127.0.0.1      # alternative à dig
```

## DHCP — Précautions

`02_mini_dhcp.py` répond aux broadcasts UDP port 67.
**Ne jamais lancer sur un réseau avec un vrai serveur DHCP** :
deux serveurs DHCP sur le même réseau = adresses IP conflictuelles.

Utiliser en environnement isolé :
- VM VirtualBox/VMware en mode réseau "host-only"
- Namespace réseau Linux : `ip netns add test`

## Format binaire DNS (RFC 1035)

```
Labels : \x03www\x06google\x03com\x00  ← "www.google.com"
          ^longueur ^label  ^longueur ^label ^fin
```
