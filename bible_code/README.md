# Bible du Réseau par le Code

La "bible intermédiaire" — entre la théorie et la vulgarisation.
Chaque script montre comment un protocole fonctionne **réellement**, en Python pur (stdlib uniquement).

## Structure

| Module | Couche OSI | Ce qu'on construit |
|---|---|---|
| `module_01_liaison/` | Couche 2 | Sniffer Ethernet, forger des paquets ARP |
| `module_02_transport/` | Couche 4 | Serveur UDP, TCP + Three-Way Handshake |
| `module_03_services/` | Services réseau | Serveur DNS, serveur DHCP |
| `module_04_application/` | Couche App | Serveur HTTP, Proxy HTTP, Proxy HTTPS |

## Prérequis

- Python 3.8+
- Linux (les modules 1 et 2 utilisent `AF_PACKET`, spécifique Linux)
- Certains scripts nécessitent `sudo` (bind sur ports < 1024, accès raw sockets)

## Ligne éditoriale

Chaque script :
1. Commence par une **analogie** de la vie réelle
2. Montre la **structure binaire** du protocole
3. Fait moins de **80 lignes** de code actif
4. Utilise **uniquement `socket`, `struct`, `threading`, `select`**
5. Se termine par les **commandes de test** (`dig`, `curl`, `tcpdump`)

## Ordre de lecture recommandé

```
01_liaison → 02_transport → 03_services → 04_application
```

Chaque module réutilise les concepts du précédent.
