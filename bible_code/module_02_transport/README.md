# Module 2 — Couche Transport (UDP / TCP)

**Prérequis :** Python 3.8+, pas de `sudo` nécessaire (ports > 1024)

| Fichier | Ce qu'il fait | Commande de test |
|---|---|---|
| `01_udp_echo.py` | Serveur + client UDP, écho simple | `python3 01_udp_echo.py serveur` puis `client` |
| `02_tcp_handshake.py` | Serveur + client TCP, observe le handshake | `python3 02_tcp_handshake.py serveur` puis `client` |

## Voir le Three-Way Handshake en direct

```bash
# Terminal 1 — lancer le sniffer AVANT le serveur
sudo tcpdump -i lo tcp port 9998 -n

# Terminal 2 — serveur
python3 02_tcp_handshake.py serveur

# Terminal 3 — client
python3 02_tcp_handshake.py client
```

Vous verrez : `SYN` → `SYN-ACK` → `ACK` puis `FIN` → `ACK` à la fermeture.

## Résumé UDP vs TCP

| Critère | UDP | TCP |
|---|---|---|
| Connexion | Non | Oui (3-Way Handshake) |
| Ordre garanti | Non | Oui |
| Fiabilité | Non | Oui (retransmission) |
| Vitesse | Plus rapide | Plus lent |
| Usage | DNS, DHCP, streaming | Web, SSH, email |
