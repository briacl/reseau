# BIBLE RÉSEAUX — R&T BUT 1ère Année
### Référentiel technique complet | Briac Le Meillat

> Ce document synthétise l'ensemble des connaissances réseau acquises en 1ère année de BUT Réseaux & Télécommunications. Il est conçu comme un livre de référence : chaque chapitre est indépendant et peut devenir un document séparé.

---

## TABLE DES MATIÈRES

1. [Fondamentaux Numériques](#1-fondamentaux-numériques)
2. [Architecture d'Internet](#2-architecture-dinternet)
3. [Modèles OSI et TCP/IP](#3-modèles-osi-et-tcpip)
4. [Adressage IPv4](#4-adressage-ipv4)
5. [Adressage IPv6](#5-adressage-ipv6)
6. [Ethernet et ARP](#6-ethernet-et-arp)
7. [IP et ICMP](#7-ip-et-icmp)
8. [Transport : TCP et UDP](#8-transport--tcp-et-udp)
9. [Protocoles Applicatifs](#9-protocoles-applicatifs)
10. [Routage — Principes et Statique](#10-routage--principes-et-statique)
11. [Routage Dynamique : RIP et OSPF](#11-routage-dynamique--rip-et-ospf)
12. [VLAN et Trunk 802.1Q](#12-vlan-et-trunk-8021q)
13. [Routage Inter-VLAN (Router-on-a-Stick)](#13-routage-inter-vlan-router-on-a-stick)
14. [Spanning Tree Protocol (STP)](#14-spanning-tree-protocol-stp)
15. [EtherChannel](#15-etherchannel)
16. [Passerelle Linux (NAT & IP Forwarding)](#16-passerelle-linux-nat--ip-forwarding)
17. [Filtrage Réseau Linux (iptables & nftables)](#17-filtrage-réseau-linux-iptables--nftables)
18. [ACL — Listes de Contrôle d'Accès](#18-acl--listes-de-contrôle-daccès)
19. [La Virtualisation](#19-la-virtualisation)
20. [Les Clusters et la Haute Disponibilité](#20-les-clusters-et-la-haute-disponibilité)
21. [Le Cloud et le Green Computing](#21-le-cloud-et-le-green-computing)
22. [Serveurs Web : Apache2 et Nginx](#22-serveurs-web--apache2-et-nginx)
23. [Téléphonie sur IP (VoIP / Asterisk)](#23-téléphonie-sur-ip-voip--asterisk)
24. [Le Web : De l'URL à l'écran](#24-le-web--de-lurl-à-lécran)
25. [Anatomie d'un Navigateur Web](#25-anatomie-dun-navigateur-web)
26. [La Programmation : PHP et Python](#26-la-programmation--php-et-python)
27. [Administration Cisco IOS — Aide-mémoire](#27-administration-cisco-ios--aide-mémoire)
28. [Commandes Réseau Linux — Aide-mémoire](#28-commandes-réseau-linux--aide-mémoire)
29. [Administration Windows Server & Active Directory](#29-administration-windows-server--active-directory)

---

## 1. Fondamentaux Numériques

### 1.1 Le Bit

Le **bit** (Binary Digit) est l'unité élémentaire d'information. Il correspond aux deux états physiques d'un transistor :
- **1** : le courant passe (ON).
- **0** : le courant ne passe pas (OFF).

Avec **n** bits, on peut créer **2ⁿ** séquences différentes :

| Nombre de bits | Nombre de combinaisons | Plage décimale |
|:-:|:-:|:-:|
| 1 | 2 | 0 – 1 |
| 4 (nibble) | 16 | 0 – 15 |
| 8 (octet) | 256 | 0 – 255 |
| 16 | 65 536 | 0 – 65 535 |
| 32 | ~4,3 milliards | — |
| 128 | ~3,4 × 10³⁸ | — |

Tout l'adressage réseau repose sur ce principe. Une adresse IPv4 est un nombre de 32 bits ; une adresse IPv6 est un nombre de 128 bits ; une adresse MAC est un nombre de 48 bits.

---

### 1.2 Conversion Binaire ↔ Décimal

**Binaire → Décimal** : chaque position vaut 2ⁿ en partant de la droite (2⁰ = 1).

```
Position :  2⁷  2⁶  2⁵  2⁴  2³  2²  2¹  2⁰
Valeur   : 128   64   32   16   8    4    2    1
```

**Exemple** : `11000000` = 128 + 64 = **192**

**Table de référence rapide pour les octets de masque :**

| Binaire | Décimal | Bits à 1 |
|---|:-:|:-:|
| `00000000` | 0 | 0 |
| `10000000` | 128 | 1 |
| `11000000` | 192 | 2 |
| `11100000` | 224 | 3 |
| `11110000` | 240 | 4 |
| `11111000` | 248 | 5 |
| `11111100` | 252 | 6 |
| `11111110` | 254 | 7 |
| `11111111` | 255 | 8 |

> Ces valeurs sont appelées les **"nombres magiques"** du masque. Tout octet d'un masque valide appartient nécessairement à cette liste.

**Décimal → Binaire** : soustraire les puissances de 2 en partant de la plus grande.

**Exemple** : 172 = 128 + 32 + 8 + 4 = `10101100`

---

### 1.3 Hexadécimal (Base 16)

L'hexadécimal est utilisé pour représenter des données binaires de façon lisible.

**16 symboles** : `0 1 2 3 4 5 6 7 8 9 A B C D E F`

| Hex | Décimal | Binaire |
|:-:|:-:|:-:|
| 0 | 0 | 0000 |
| 9 | 9 | 1001 |
| A | 10 | 1010 |
| F | 15 | 1111 |

**Règle clé** : 1 caractère hex = 4 bits (1 nibble). Donc 1 octet = 2 caractères hex.

Exemples : `FF` = 255, `0x0800` = type IPv4 dans Ethernet, `0x0806` = type ARP.

Utilisations en réseau :
- Adresses MAC : `ab:cd:ef:00:11:22` (6 octets = 12 caractères hex)
- Adresses IPv6 : `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
- Champs de protocoles : EtherType, OpCode ARP, etc.

---

## 2. Architecture d'Internet

### 2.1 Internet : un réseau de réseaux

Internet n'est pas un réseau centralisé géré par une entité unique. C'est l'interconnexion d'environ **80 000 Systèmes Autonomes (AS)** indépendants, reliés entre eux par des accords techniques et commerciaux.

**Infrastructure physique :**
- **Câbles sous-marins** : plus de 150 câbles en fibre optique posés au fond des océans, représentant ~1,3 million de kilomètres. Ils transportent plus de 95 % du trafic Internet intercontinental (et non les satellites).
- **Points d'atterrissage (landing stations)** : installations côtières où les câbles sous-marins rejoignent le réseau terrestre.

**Hiérarchie des opérateurs :**

| Niveau | Nom | Description | Exemple |
|:-:|---|---|---|
| **Tier 1** | Opérateurs mondiaux | Possèdent des backbones planétaires. S'échangent le trafic gratuitement (peering). N'achètent de transit à personne. | AT&T, Lumen, NTT, Telia |
| **Tier 2** | Opérateurs régionaux | Peerent avec certains Tier 1, achètent du transit pour le reste. | Orange (hors France), Zayo |
| **Tier 3** | FAI locaux | Achètent du transit auprès des Tier 1/2. N'ont pas de backbone propre. | FAI locaux, hébergeurs |

---

### 2.2 Le Système Autonome (AS)

Un **AS (Autonomous System)** est un ensemble de réseaux IP placé sous une même politique de routage et géré par une entité unique (entreprise, université, opérateur).

- Chaque AS possède un numéro unique appelé **ASN** (Autonomous System Number)
  - Format 16 bits (historique) : 1 – 65 535
  - Format 32 bits (moderne, RFC 4893) : jusqu'à ~4,3 milliards
- Attribution : par les RIR (Regional Internet Registries) — RIPE NCC pour l'Europe

**Exemples d'ASN connus :**

| ASN | Entité |
|:-:|---|
| AS3215 | Orange France |
| AS5410 | Bouygues Telecom |
| AS12322 | Free (Proxad) |
| AS15169 | Google |
| AS2200 | RENATER (réseau académique français) |
| AS32934 | Meta (Facebook) |

```bash
# Vérifier l'ASN d'une adresse IP ou d'un réseau (Linux)
whois -h whois.radb.net AS15169
whois 8.8.8.8 | grep -i "origin\|as-name"
```

---

### 2.3 BGP (Border Gateway Protocol)

**BGP** est le protocole de routage qui relie les AS entre eux. C'est le seul protocole de routage inter-domaine utilisé sur Internet.

**Différence fondamentale avec OSPF/RIP :**

| Critère | OSPF / RIP (intra-AS) | BGP (inter-AS) |
|---|---|---|
| Portée | À l'intérieur d'un seul AS | Entre AS différents |
| Métrique | Plus court chemin (coût/sauts) | Chemin politiquement/commercialement préféré |
| Convergence | Rapide (secondes) | Lente (minutes) |
| Encapsulation | IP (OSPF=89) / UDP (RIP=520) | TCP port **179** |

**Deux variantes :**
- **eBGP** (external BGP) : session entre routeurs de **deux AS différents**. Échangent les préfixes IP qu'ils annoncent.
- **iBGP** (internal BGP) : session entre routeurs **à l'intérieur du même AS**, pour propager les routes BGP apprises en interne.

**Attributs BGP clés :**

| Attribut | Rôle |
|---|---|
| **AS_PATH** | Liste des AS traversés par l'annonce. Détecte les boucles (on n'accepte pas sa propre annonce). |
| **NEXT_HOP** | Adresse IP du prochain routeur à joindre |
| **LOCAL_PREF** | Préférence locale (plus élevé = préféré), utilisé en iBGP |
| **MED** (Multi-Exit Discriminator) | Suggère au voisin quel chemin préférer pour entrer dans notre AS |

---

### 2.4 Les Points d'Échange Internet (IXP)

Un **IXP (Internet Exchange Point)** est une infrastructure physique neutre — généralement un datacenter — où plusieurs AS se connectent directement via des **switches haute capacité** pour s'échanger du trafic local.

**Avantages du peering en IXP :**
- Trafic régional qui reste régional (pas besoin de passer par un Tier 1 américain)
- Latence réduite et coût inférieur au transit payant
- Résilience : si un opérateur tombe, le trafic peut passer par d'autres membres de l'IXP

**IXP majeurs :**

| IXP | Localisation | Trafic de pointe |
|---|---|---|
| **DE-CIX** | Francfort | > 14 Tbps (le plus grand au monde) |
| **AMS-IX** | Amsterdam | > 10 Tbps |
| **France-IX** | Paris | > 3 Tbps |
| **LINX** | Londres | > 7 Tbps |

**Route Servers** : équipements centraux gérés par l'IXP qui redistribuent automatiquement les annonces BGP entre tous les membres — chaque membre n'a besoin que d'une session BGP vers le route server, pas d'une session vers chaque autre membre.

---

### 2.5 Chemin d'un paquet à travers Internet

```
[Ton PC]
    │ routage local (LAN)
[Box FAI — Tier 3]
    │ transit acheté au Tier 2
[Routeur Tier 2 régional]
    │ peering à l'IXP ou transit Tier 1
[IXP / Routeur Tier 1]
    │ backbone mondial (câbles sous-marins si intercontinental)
[Routeur Tier 1 destination]
    │ transit vers Tier 2/3 de destination
[Serveur destination]
```

À chaque flèche : un routeur BGP prend une **décision autonome** basée sur ses tables de routage et ses politiques. Les IPs source/destination ne changent pas — seules les MACs changent à chaque saut.

**Commandes utiles pour observer le chemin :**
```bash
traceroute -A 8.8.8.8   # -A affiche le numéro d'AS à chaque saut (Linux)
mtr --aslookup 8.8.8.8  # vue en temps réel avec ASN (nécessite mtr)
```

---

## 3. Modèles OSI et TCP/IP

### 3.1 Comparaison des deux modèles

| Couche OSI | N° | Couche TCP/IP | Protocoles/technologies |
|---|:-:|---|---|
| Application | 7 | Application | HTTP, HTTPS, SSH, FTP, DNS, DHCP, SIP |
| Présentation | 6 | Application | TLS/SSL |
| Session | 5 | Application | — |
| Transport | 4 | Transport | TCP, UDP |
| Réseau | 3 | Internet | IP (v4/v6), ICMP, OSPF |
| Liaison de données | 2 | Accès réseau | Ethernet (802.3), Wi-Fi (802.11), ARP |
| Physique | 1 | Accès réseau | Câbles, fibres, ondes radio |

### 3.2 Principes d'encapsulation

Chaque couche **encapsule** les données de la couche supérieure en ajoutant son propre en-tête (et éventuellement un pied de trame).

```
Application  →  [Données]
Transport    →  [TCP/UDP en-tête | Données]
Réseau       →  [IP en-tête | TCP/UDP en-tête | Données]
Liaison      →  [ETH en-tête | IP | TCP/UDP | Données | ETH CRC]
Physique     →  Bits sur le médium
```

**Encapsulations classiques dans un réseau Ethernet filaire :**

| Trafic | Encapsulation |
|---|---|
| Ping | ETH \| IP \| ICMP |
| Navigation web | ETH \| IP \| TCP \| HTTP |
| Administration SSH | ETH \| IP \| TCP \| SSH |
| Résolution DNS | ETH \| IP \| UDP \| DNS |
| Attribution IP | ETH \| IP \| UDP \| DHCP |
| Résolution MAC | ETH \| ARP |
| Transfert fichier | ETH \| IP \| TCP \| FTP |

### 3.3 Rôle des couches — ce que chaque couche "voit"

**Couche Physique (1)** : transmet les bits bruts sur le support physique (signal électrique, optique, radio). Ne connaît que des 0 et des 1.

**Couche Liaison (2)** : délimite les **trames**, détecte les erreurs (CRC), gère l'accès au médium (CSMA/CD). Adresse : **MAC** (48 bits). Portée : **locale** (LAN). Un switch travaille à cette couche.

**Couche Réseau (3)** : route les **paquets** entre réseaux. Adresse : **IP** (32 bits en IPv4). Portée : **globale** (Internet). Un routeur travaille à cette couche.

**Couche Transport (4)** : gère la communication de **bout en bout** entre processus. Utilise les **numéros de port** pour le multiplexage. Protocoles : TCP (fiable) ou UDP (rapide).

**Couche Application (5-7)** : services utilisateurs (web, mail, DNS, etc.).

---

## 4. Adressage IPv4

### 4.1 Structure d'une adresse IPv4

Une adresse IPv4 est un nombre de **32 bits** écrit en notation décimale pointée : 4 octets séparés par des points.

```
Décimal  :  192   .  168   .   10   .   234
Binaire  : 11000000.10101000.00001010.11101010
```

Chaque octet vaut entre 0 et 255. L'adresse IP est **toujours accompagnée d'un masque** pour être exploitable.

### 4.2 Masque de sous-réseau

Le masque est une suite de 32 bits qui divise l'adresse IP en deux parties :
- Les bits à **1** → partie **RÉSEAU (NetID)** : identifie le groupe
- Les bits à **0** → partie **MACHINE (HostID)** : identifie l'hôte dans ce groupe

**Règle de validité absolue** : un masque valide est **obligatoirement** une suite ininterrompue de 1 suivie d'une suite ininterrompue de 0. Exemple invalide : `255.0.0.255` car il y a des 1 après des 0.

**Deux notations équivalentes :**

| Notation décimale | Notation CIDR | Bits à 1 | Bits à 0 |
|---|:-:|:-:|:-:|
| `255.0.0.0` | `/8` | 8 | 24 |
| `255.255.0.0` | `/16` | 16 | 16 |
| `255.255.255.0` | `/24` | 24 | 8 |
| `255.255.255.128` | `/25` | 25 | 7 |
| `255.255.255.192` | `/26` | 26 | 6 |
| `255.255.255.224` | `/27` | 27 | 5 |
| `255.255.255.240` | `/28` | 28 | 4 |
| `255.255.255.248` | `/29` | 29 | 3 |
| `255.255.255.252` | `/30` | 30 | 2 |

### 4.3 Calcul de l'adresse réseau (ET logique)

Pour trouver l'adresse réseau, on applique un **ET logique (AND) bit à bit** entre l'adresse IP et le masque.

| A | B | A AND B |
|:-:|:-:|:-:|
| 1 | 1 | **1** |
| 1 | 0 | **0** |
| 0 | 0 | **0** |
| 0 | 1 | **0** |

**Exemple** : `192.168.10.234/24`
```
IP     : 11000000.10101000.00001010.11101010  (192.168.10.234)
Masque : 11111111.11111111.11111111.00000000  (255.255.255.0)
AND    : 11000000.10101000.00001010.00000000  = 192.168.10.0
```
→ L'adresse réseau est `192.168.10.0`.

**Raccourci pratique** : avec un `/24`, les 3 premiers octets constituent la partie réseau, le dernier est mis à 0. Avec un `/16`, les 2 premiers octets forment la partie réseau.

### 4.4 Adresse réseau et adresse de broadcast

Dans chaque réseau, **deux adresses sont réservées** et ne peuvent jamais être assignées à un hôte :

| Adresse | Comment l'obtenir | Rôle |
|---|---|---|
| **Adresse réseau** | Tous les bits HostID à **0** | Identifiant du réseau, utilisé dans les tables de routage |
| **Adresse de broadcast** | Tous les bits HostID à **1** | Envoi à tous les hôtes du réseau simultanément (ARP, DHCP) |

**Exemples :**

| Réseau CIDR | Adresse réseau | Broadcast | Plage utilisable |
|---|---|---|---|
| `11.12.13.14/8` | `11.0.0.0` | `11.255.255.255` | `11.0.0.1` – `11.255.255.254` |
| `172.31.5.10/16` | `172.31.0.0` | `172.31.255.255` | `172.31.0.1` – `172.31.255.254` |
| `200.1.23.45/24` | `200.1.23.0` | `200.1.23.255` | `200.1.23.1` – `200.1.23.254` |
| `192.168.1.128/25` | `192.168.1.128` | `192.168.1.255` | `192.168.1.129` – `192.168.1.254` |
| `192.168.10.0/26` | `192.168.10.0` | `192.168.10.63` | `192.168.10.1` – `192.168.10.62` |
| `10.1.4.32/27` | `10.1.4.32` | `10.1.4.63` | `10.1.4.33` – `10.1.4.62` |

### 4.5 Calcul du nombre d'hôtes

$$\text{Nombre d'hôtes utilisables} = 2^n - 2$$

Où **n** = nombre de bits à 0 dans le masque (= 32 − CIDR).

Le `−2` exclut l'adresse réseau et l'adresse de broadcast.

| Préfixe | Bits hôte | Total adresses | Hôtes utilisables |
|:-:|:-:|:-:|:-:|
| /30 | 2 | 4 | **2** |
| /29 | 3 | 8 | **6** |
| /28 | 4 | 16 | **14** |
| /27 | 5 | 32 | **30** |
| /26 | 6 | 64 | **62** |
| /25 | 7 | 128 | **126** |
| /24 | 8 | 256 | **254** |
| /23 | 9 | 512 | **510** |
| /22 | 10 | 1 024 | **1 022** |
| /20 | 12 | 4 096 | **4 094** |
| /16 | 16 | 65 536 | **65 534** |
| /10 | 22 | 4 194 304 | **4 194 302** |
| /8 | 24 | 16 777 216 | **16 777 214** |

**Cas particulier `/30`** : seulement 2 hôtes utilisables. Utilisé pour les liaisons point-à-point entre routeurs (un réseau = les 2 routeurs + adresse réseau + broadcast).

### 4.6 Classes IP historiques

Avant le CIDR (Classless Inter-Domain Routing), les adresses étaient regroupées en classes rigides :

| Classe | 1ers bits | Plage | Masque par défaut | Nb de réseaux / hôtes |
|:-:|:-:|---|:-:|---|
| A | `0` | `0.0.0.0` – `127.255.255.255` | /8 | 128 réseaux × 16M hôtes |
| B | `10` | `128.0.0.0` – `191.255.255.255` | /16 | 16 384 réseaux × 65 534 hôtes |
| C | `110` | `192.0.0.0` – `223.255.255.255` | /24 | 2M réseaux × 254 hôtes |
| D | `1110` | `224.0.0.0` – `239.255.255.255` | — | Multicast |
| E | `1111` | `240.0.0.0` – `255.255.255.255` | — | Réservé |

Le CIDR a remplacé ce système pour utiliser les adresses plus efficacement, permettant des masques de n'importe quelle longueur.

### 4.7 Adresses privées (RFC 1918)

Ces plages sont réservées aux réseaux internes (LAN). Elles ne sont **pas routables sur Internet**.

| Classe | Plage | CIDR | Usage typique |
|:-:|---|:-:|---|
| A | `10.0.0.0` – `10.255.255.255` | /8 | Grandes entreprises |
| B | `172.16.0.0` – `172.31.255.255` | /12 | Moyennes entreprises |
| C | `192.168.0.0` – `192.168.255.255` | /16 | Domicile, PME |

**Adresses spéciales à connaître :**

| Adresse | Signification |
|---|---|
| `127.0.0.1` | Loopback — test de la pile TCP/IP locale |
| `0.0.0.0` | Route par défaut (vers tout) |
| `255.255.255.255` | Broadcast limité (tout le réseau local) |
| `169.254.x.x` | APIPA — adresse auto-assignée quand DHCP échoue |

### 4.8 Stratégie d'adressage

Dans la pratique, on organise la plage d'un réseau ainsi :

- **Premières adresses (.1 à .20)** → équipements fixes : serveurs, imprimantes, commutateurs
- **Adresses centrales (.50 à .150)** → pool DHCP pour postes clients
- **Dernières adresses (.254)** → interfaces de routeurs/passerelles

**Exemple `/24` :**
```
192.168.1.0       Adresse réseau (réservée)
192.168.1.1       Serveur principal
192.168.1.10      Serveur DNS
192.168.1.50-150  Pool DHCP
192.168.1.254     Interface routeur (gateway)
192.168.1.255     Broadcast (réservé)
```

### 4.9 Découpage en sous-réseaux

Combien de sous-réseaux `/26` dans un `/24` ?  
Chaque `/26` = 64 adresses. Un `/24` = 256 adresses. → 256 / 64 = **4 sous-réseaux**.

Règle générale : augmenter le préfixe de **n bits** crée **2ⁿ** sous-réseaux.

| Réseau original | Sous-réseaux | Préfixe résultant | Hôtes/sous-réseau |
|---|:-:|:-:|:-:|
| `/24` découpé en 2 | 2 | `/25` | 126 |
| `/24` découpé en 4 | 4 | `/26` | 62 |
| `/24` découpé en 8 | 8 | `/27` | 30 |
| `/24` découpé en 16 | 16 | `/28` | 14 |

---

## 5. Adressage IPv6

### 5.1 Pourquoi IPv6 ?

IPv4 offre ~4,3 milliards d'adresses (2³²). Face à la prolifération des objets connectés, ces adresses sont épuisées. IPv6 résout ce problème radicalement.

| Critère | IPv4 | IPv6 |
|---|---|---|
| Longueur | 32 bits | 128 bits |
| Notation | Décimale pointée | Hexadécimale groupée |
| Espace | ~4,3 milliards | ~3,4 × 10³⁸ (340 sextillions) |
| En-tête | Variable (20–60 octets) | Fixe (40 octets) |
| NAT | Nécessaire | Inutile (assez d'adresses) |

### 5.2 Notation IPv6

Format : **8 groupes de 4 caractères hexadécimaux** séparés par `:`.

Exemple complet : `2001:0db8:85a3:0000:0000:8a2e:0370:7334`

**Règles d'abréviation :**
1. Supprimer les zéros de tête dans chaque groupe : `0db8` → `db8`
2. Remplacer une suite de groupes nuls par `::` (une seule fois par adresse)

`2001:0db8:0000:0000:0000:0000:0000:0001` → `2001:db8::1`

**Adresses spéciales IPv6 :**

| Adresse | Signification |
|---|---|
| `::1` | Loopback (équivalent de `127.0.0.1`) |
| `fe80::/10` | Lien-local (non routable, portée d'un seul lien) |
| `ff02::1` | Tous les nœuds du lien (multicast) |

---

## 6. Ethernet et ARP

### 6.1 Ethernet (IEEE 802.3)

Ethernet est le protocole dominant pour les réseaux locaux filaires. Il opère aux couches 1 et 2.

**Caractéristiques physiques :**

| Catégorie | Débit max | Distance max |
|:-:|:-:|:-:|
| Cat 5 | 100 Mbps | 100 m |
| Cat 5e | 1 Gbps | 100 m |
| Cat 6 | 10 Gbps (courte distance) | 55 m (10G) / 100 m (1G) |
| Cat 6a/7 | 10 Gbps | 100 m |

**Connecteur** : RJ45. Câble droit (PC→Switch) ou câble croisé (Switch→Switch, ancien). Les équipements modernes ont l'**Auto MDI-X** qui détecte automatiquement.

**Trame Ethernet :**
```
[Préambule 7B | SFD 1B | MAC Dest 6B | MAC Src 6B | EtherType 2B | Données | CRC 4B]
```

| Champ | Taille | Valeurs notables |
|---|:-:|---|
| MAC Destination | 6 octets | `FF:FF:FF:FF:FF:FF` = broadcast |
| MAC Source | 6 octets | Adresse de l'émetteur |
| EtherType | 2 octets | `0x0800` = IPv4, `0x0806` = ARP, `0x86DD` = IPv6, `0x8100` = 802.1Q VLAN |
| Données | 46–1500 octets | Payload |
| CRC | 4 octets | Contrôle d'intégrité |

**Gestion des collisions** : protocole **CSMA/CD** (Carrier Sense Multiple Access / Collision Detection). Écoute avant d'émettre, détecte les collisions et attend un délai aléatoire avant de réémettre. Rendu inutile par les switches (chaque port = domaine de collision distinct).

**Adresse MAC** :
- 48 bits (6 octets en hexadécimal, ex : `ab:cd:ef:00:11:22`)
- Les 3 premiers octets = **OUI** (Organizationally Unique Identifier) : identifie le fabricant
- Les 3 derniers octets = **NIC** (Network Interface Controller) : identifie l'interface
- **Rôle local uniquement** : l'adresse MAC de destination dans une trame est toujours celle du **prochain saut**, pas de la destination finale

**Table MAC d'un switch (CAM table)** :
- Le switch apprend les adresses MAC en examinant la MAC source de chaque trame reçue
- Il associe chaque MAC au port physique d'arrivée
- Si la MAC de destination est inconnue → **flooding** (envoi sur tous les ports sauf source)
- Si connue → **commutation sélective** (envoi uniquement vers le bon port)

### 6.2 ARP (Address Resolution Protocol)

**Problème résolu** : on connaît l'IP de destination, mais on a besoin de sa MAC pour construire la trame Ethernet.

**Fonctionnement :**

1. **Requête ARP** (broadcast) : `"Who has 192.168.1.10? Tell 192.168.1.1"`
   - MAC Destination : `FF:FF:FF:FF:FF:FF` (broadcast)
   - EtherType : `0x0806`
   - OpCode : `1` (request)

2. **Réponse ARP** (unicast) : `"192.168.1.10 is at aa:bb:cc:dd:ee:ff"`
   - MAC Destination : adresse MAC de celui qui a posé la question
   - OpCode : `2` (reply)

**Cache ARP** : les associations IP→MAC sont mémorisées temporairement pour éviter de répéter les requêtes.  
Commande Linux : `ip n` ou `arp -a` (Windows)

**Champs ARP :**

| Champ | Valeur (Ethernet/IPv4) |
|---|---|
| HTYPE | `0x0001` (Ethernet) |
| PTYPE | `0x0800` (IPv4) |
| HLEN | `6` (MAC = 6 octets) |
| PLEN | `4` (IPv4 = 4 octets) |
| OpCode | `1` (request) ou `2` (reply) |

**Gratuitous ARP** : machine qui annonce elle-même sa propre adresse IP (lors d'un changement d'IP ou pour mettre à jour les caches des voisins).

---

## 7. IP et ICMP

### 7.1 En-tête IPv4

Un paquet IPv4 commence très souvent par **`0x4500`** :
- `4` = Version IPv4
- `5` = IHL (Internet Header Length) = 5 × 4 octets = 20 octets (sans options)
- `00` = DSCP/ECN (QoS par défaut)

**Champs importants de l'en-tête IPv4 :**

| Champ | Taille | Rôle |
|---|:-:|---|
| Version | 4 bits | `4` pour IPv4 |
| IHL | 4 bits | Longueur de l'en-tête en mots de 4 octets |
| TTL | 8 bits | Time To Live : décrémenté à chaque saut, paquet détruit à 0 |
| Protocol | 8 bits | `1` = ICMP, `6` = TCP, `17` = UDP, `89` = OSPF |
| IP Source | 32 bits | Adresse de l'émetteur |
| IP Destination | 32 bits | Adresse du destinataire final |
| Identification | 16 bits | Identifie les fragments d'un paquet fragmenté |
| DF (Don't Fragment) | 1 bit | `1` = ne pas fragmenter (si nécessaire, détruire le paquet) |
| MF (More Fragments) | 1 bit | `1` = ce paquet est un fragment, il y en a d'autres |
| Fragment Offset | 13 bits | Position du fragment en blocs de 8 octets |

**TTL** : valeur maximale = 255 (8 bits). Valeurs initiales typiques : 64 (Linux), 128 (Windows), 255 (Cisco IOS). Permet d'éviter les boucles de routage infinies. C'est la base du fonctionnement de **traceroute** (on envoie des paquets avec TTL 1, 2, 3... et on collecte les messages "Time Exceeded" pour tracer le chemin).

### 7.2 ICMP (Internet Control Message Protocol)

ICMP est encapsulé dans IP (Protocol = 1). Il transporte des messages de contrôle et d'erreur.

**Messages ICMP principaux :**

| Type | Code | Nom | Usage |
|:-:|:-:|---|---|
| 0 | 0 | Echo Reply | Réponse au ping |
| 3 | 0 | Destination Unreachable – Net | Réseau injoignable |
| 3 | 1 | Destination Unreachable – Host | Hôte injoignable |
| 3 | 3 | Destination Unreachable – Port | Port injoignable (courant avec UDP) |
| 8 | 0 | Echo Request | Envoi d'un ping |
| 11 | 0 | Time Exceeded | TTL expiré (utilisé par traceroute) |

**Fonctionnement de ping :**
1. La source envoie un **Echo Request** (Type 8) vers la destination
2. La destination répond avec un **Echo Reply** (Type 0)
3. Si un routeur intermédiaire ne peut pas router → **Destination Unreachable**

**Fonctionnement de traceroute :**
1. Envoie un ICMP Echo Request avec TTL=1 → le premier routeur répond avec "Time Exceeded"
2. TTL=2 → le deuxième routeur répond
3. Et ainsi de suite jusqu'à la destination

---

## 8. Transport : TCP et UDP

### 8.1 Numéros de port

Les ports permettent le **multiplexage** : plusieurs applications peuvent utiliser le réseau simultanément sur la même machine.

**Plages de ports :**

| Plage | Type | Exemples |
|---|---|---|
| 0 – 1023 | Ports bien connus (Well-Known) | HTTP:80, HTTPS:443, SSH:22, DNS:53 |
| 1024 – 49151 | Ports enregistrés (Registered) | — |
| 49152 – 65535 | Ports éphémères (Ephemeral) | Ports clients dynamiques |

**Ports à mémoriser absolument :**

| Port | Protocole | Transport |
|:-:|---|:-:|
| 20/21 | FTP (données/contrôle) | TCP |
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | UDP (principalement) / TCP |
| 67 | DHCP serveur | UDP |
| 68 | DHCP client | UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 143 | IMAP | TCP |
| 443 | HTTPS | TCP |
| 520 | RIP | UDP |
| 5060 | SIP (VoIP) | UDP |

### 8.2 UDP (User Datagram Protocol)

**Caractéristiques :**
- **Non orienté connexion** : pas de phase d'établissement
- **Pas de fiabilité** : pas d'accusé de réception, pas de retransmission
- **Pas de garantie d'ordre** : les datagrammes peuvent arriver dans le désordre
- **Très faible overhead** : en-tête de seulement 8 octets
- **Faible latence**

**En-tête UDP :**
```
[Port source 2B | Port destination 2B | Longueur 2B | Checksum 2B]
```

**Usages** : DNS, DHCP, NTP, streaming vidéo/audio, VoIP (SIP, RTP), jeux en ligne.

### 8.3 TCP (Transmission Control Protocol)

**Caractéristiques :**
- **Orienté connexion** : établissement obligatoire avant envoi
- **Fiable** : accusés de réception (ACK), retransmission si perte
- **Ordonné** : numérotation des octets, remise dans l'ordre
- **Contrôle de flux** : mécanisme de fenêtre glissante
- **Contrôle de congestion** : adaptation du débit aux conditions réseau

**En-tête TCP :**
```
[Port src 2B | Port dest 2B | Seq 4B | Ack 4B | Flags 2B | Window 2B | Checksum 2B | ...]
```

**Flags TCP :**

| Flag | Rôle |
|:-:|---|
| **SYN** | Synchronisation — initie ou accepte une connexion |
| **ACK** | Acquittement — confirme la réception |
| **FIN** | Fin — fermeture ordonnée d'un sens de communication |
| **RST** | Reset — fermeture brutale (port fermé, erreur grave) |
| **PSH** | Push — transmettre immédiatement sans attendre le remplissage du buffer |
| **URG** | Urgent — données prioritaires |

**Établissement de connexion — 3-way handshake :**

```
Client                    Serveur
   |  ----  SYN  -------> |   SEQ=x
   |  <-- SYN, ACK -----  |   SEQ=y, ACK=x+1
   |  ----  ACK  -------> |   ACK=y+1
   |   [connexion établie] |
```

**Fermeture — 4-way (half-close) :**

```
Client                    Serveur
   |  -- FIN, ACK ------> |   Client fini d'envoyer
   |  <---- ACK ---------  |   Serveur acquitte
   |  <-- FIN, ACK ------  |   Serveur fini d'envoyer
   |  ------ ACK -------> |   Client acquitte
   |   [connexion fermée]  |
```

**Numéros de séquence et d'acquittement :**
- `Seq` : numéro du premier octet de ce segment
- `Ack` : numéro du prochain octet attendu = Seq + Len du segment reçu
- Règle : `Ack = Seq_reçu + Len_données`

**Contrôle de flux — fenêtre (Window) :**
- Le champ `Window` (16 bits max = 65 535 octets) indique combien d'octets le récepteur peut encore accepter
- L'option **Window Scale** (négociée au SYN) permet d'augmenter cette valeur pour les liaisons haut débit

**Gestion d'erreur — Binary Exponential Backoff :**
En cas de perte, TCP double le délai d'attente avant chaque retransmission (1s, 2s, 4s, 8s...). Linux abandonne après ~15 minutes.

**TCP vs UDP — tableau de synthèse :**

| Critère | TCP | UDP |
|---|---|---|
| Connexion | 3-way handshake | Aucune |
| Fiabilité | ACK + retransmission | Aucune garantie |
| Ordre | Garanti | Non garanti |
| Vitesse | Plus lent | Plus rapide |
| En-tête | 20 octets min | 8 octets |
| Usages | HTTP, SSH, FTP | DNS, DHCP, VoIP, streaming |

---

## 9. Protocoles Applicatifs

### 9.1 DNS (Domain Name System)

**Rôle** : résoudre les noms de domaine en adresses IP.  
**Port** : UDP 53 (TCP 53 pour grandes réponses ou transferts de zone).  
**Encapsulation** : ETH | IP | UDP | DNS

**Types d'enregistrements (Resource Records) :**

| Type | Rôle | Exemple |
|:-:|---|---|
| **A** | Nom → IPv4 | `iut-rt.univ-artois.fr` → `172.31.25.9` |
| **AAAA** | Nom → IPv6 | `example.com` → `2001:db8::1` |
| **PTR** | IP → Nom (résolution inverse) | `9.25.31.172.in-addr.arpa` → `iut-rt` |
| **CNAME** | Alias (Nom → Nom) | `www.example.com` → `example.com` |
| **MX** | Serveur de messagerie du domaine | `mail.example.com` |
| **NS** | Serveur DNS de la zone | — |
| **SOA** | Début de zone (Start of Authority) | — |

**Outils de test DNS :**
```bash
nslookup iut-rt                # Windows/Linux — requête simple
dig iut-rt                     # Linux — sortie détaillée
host iut-rt                    # Linux — simple
```

### 9.2 DHCP (Dynamic Host Configuration Protocol)

**Rôle** : attribuer automatiquement une configuration IP à un client.  
**Ports** : UDP 67 (serveur) / UDP 68 (client).  
**Encapsulation** : ETH | IP | UDP | DHCP

**Processus DORA :**

```
Client                              Serveur DHCP
  | -- DISCOVER (broadcast) -------> |  "Y a-t-il un serveur DHCP ?"
  | <---- OFFER (unicast/broadcast)  |  "Je t'offre 192.168.1.50"
  | -- REQUEST (broadcast) --------> |  "J'accepte 192.168.1.50"
  | <---- ACK (unicast/broadcast) -- |  "C'est confirmé, voilà tes paramètres"
```

**Paramètres distribués :**
- Adresse IP
- Masque de sous-réseau
- Passerelle par défaut (default-router)
- Serveur(s) DNS
- Durée du bail (lease time)

**Si DHCP échoue** → APIPA attribue une adresse `169.254.x.x` (autoconfiguration)

**Configuration DHCP sur routeur Cisco :**
```cisco
! Exclure des adresses du pool
ip dhcp excluded-address 192.168.20.254
ip dhcp excluded-address 192.168.20.10

! Définir le pool
ip dhcp pool POOL_PERSONNEL
 network 192.168.20.0 255.255.255.0
 default-router 192.168.20.254
 dns-server 192.168.10.10
```

**Configuration DHCP sous Linux (isc-dhcp-server) :**
```text
# /etc/dhcp/dhcpd.conf
default-lease-time 3600;
max-lease-time 7200;
authoritative;

subnet 192.168.20.0 netmask 255.255.255.0 {
    range 192.168.20.50 192.168.20.150;
    option routers 192.168.20.254;
    option domain-name-servers 192.168.10.10, 1.1.1.1;
    option domain-name "vlan-personnel.net";
}
```

### 9.3 HTTP / HTTPS

**Rôle** : transfert de pages et ressources web.  
**Ports** : 80 (HTTP), 443 (HTTPS = HTTP + TLS/SSL).

**Méthodes HTTP :**

| Méthode | Rôle |
|---|---|
| GET | Demander une ressource |
| POST | Envoyer des données (formulaire) |
| PUT | Mettre à jour une ressource |
| DELETE | Supprimer une ressource |

**Codes de statut HTTP :**

| Code | Signification |
|:-:|---|
| 200 | OK — succès |
| 301/302 | Redirection |
| 404 | Not Found — ressource introuvable |
| 403 | Forbidden — accès refusé |
| 500 | Internal Server Error |

### 9.4 SSH (Secure Shell)

**Rôle** : accès distant sécurisé (shell, transfert de fichiers, tunneling).  
**Port** : TCP 22.  
**Avantage sur Telnet** : tout le trafic est chiffré.

Administration Cisco via SSH :
```cisco
! Prérequis
ip domain-name monreseau.local
crypto key generate rsa modulus 2048
username admin privilege 15 secret motdepasse

! Activer SSH v2 seulement
ip ssh version 2
line vty 0 4
 transport input ssh
 login local
```

### 9.5 FTP (File Transfer Protocol)

**Rôle** : transfert de fichiers.  
**Ports** : TCP 21 (contrôle), TCP 20 (données en mode actif) ou port dynamique (mode passif).  
**Non chiffré** par défaut → préférer **SFTP** (via SSH) ou **FTPS** (FTP + TLS).

### 9.6 PXE — Démarrage Réseau

**Rôle** : permettre à un client sans OS local de démarrer depuis le réseau en chargeant un noyau et un système de fichiers via TFTP.  
**Composants** : DHCP (options 66/67) + TFTP + NFS.  
**Cas d'usage** : déploiement en masse, terminaux légers (diskless), maintenance système.

**Flux de démarrage PXE :**

```
Client PXE
  │
  ├─ 1. DHCP DISCOVER ─────────────► Serveur DHCP
  │      (demande IP + option PXE)
  │
  ◄─ 2. DHCP OFFER ────────────────┤
  │      IP + option 66 (TFTP server IP)
  │      option 67 (boot filename, ex: pxelinux.0)
  │
  ├─ 3. TFTP GET pxelinux.0 ───────► Serveur TFTP
  │
  ◄─ 4. Transfert du bootloader ───┤
  │
  ├─ 5. Montage NFS ───────────────► Serveur NFS
  │      (root filesystem ou image OS)
  │
  └─ 6. Démarrage OS ✓
```

**Configuration isc-dhcp-server pour PXE :**
```text
# /etc/dhcp/dhcpd.conf — section PXE
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    option routers 192.168.1.1;

    next-server 192.168.1.1;       # IP du serveur TFTP
    filename "pxelinux.0";          # Bootloader PXE
}
```

**Configuration Dnsmasq (alternative tout-en-un DHCP + TFTP) :**
```text
# /etc/dnsmasq.conf
interface=eth0
dhcp-range=192.168.1.100,192.168.1.200,1h
dhcp-boot=pxelinux.0,pxeserver,192.168.1.1
enable-tftp
tftp-root=/var/lib/tftpboot
```

**Protocoles impliqués :**

| Étape | Protocole | Port | Rôle |
|---|---|:-:|---|
| Découverte IP | DHCP | UDP 67/68 | Attribution d'adresse + options boot |
| Transfert bootloader | TFTP | UDP 69 | Téléchargement du fichier de démarrage |
| Montage filesystem | NFS | TCP 2049 | Accès au rootfs distant |

**Avantage** : un seul serveur peut déployer des dizaines de machines identiques simultanément. Aucun disque local requis côté client.

---

## 10. Routage — Principes et Statique

### 10.1 Fonctionnement du routage

Un **routeur** est un équipement de couche 3 qui achemine les paquets IP d'un réseau vers un autre. Il prend sa décision en consultant sa **table de routage**.

**Processus de décision à chaque saut :**
1. Extraire l'IP de destination du paquet
2. Chercher dans la table de routage la route la plus spécifique (**Longest Prefix Match**)
3. Transmettre le paquet vers le **next-hop** (prochain saut) sur l'interface appropriée
4. Décrémenter le TTL — si TTL = 0, détruire le paquet et envoyer un ICMP Time Exceeded

**Longest Prefix Match** : si plusieurs routes correspondent, le routeur choisit celle avec le masque le plus long (le plus spécifique). `/30` est préféré à `/24` qui est préféré à `/0`.

**Rôle de la MAC dans le routage :**
- Quand un routeur reçoit un paquet, il réécrit la **MAC source** (avec sa propre MAC) et la **MAC destination** (avec la MAC du prochain équipement)
- Les IPs source et destination **ne changent jamais** pendant le routage (sauf NAT)

### 10.2 Table de routage Cisco

```
Codes: C = connected, L = local, S = static, R = RIP, O = OSPF
       * = candidate default route

R1# show ip route
C    192.168.1.0/24 is directly connected, GigabitEthernet0/0
L    192.168.1.1/32 is directly connected, GigabitEthernet0/0
S    192.168.2.0/24 [1/0] via 192.168.3.2
R    10.2.0.0/16 [120/1] via 10.1.0.2, Serial0/0/0
O    192.168.2.0/24 [110/64] via 10.1.0.2, Serial0/0/0
```

Format : `Protocole  Réseau/Préfixe  [DA/Métrique] via Next-Hop, Interface`

**Distance Administrative (DA)** : mesure de la fiabilité d'une source de route. **Plus la DA est faible, plus la route est préférée.**

| Source | DA |
|---|:-:|
| Directement connectée (C) | 0 |
| Route statique (S) | 1 |
| OSPF (O) | 110 |
| RIP (R) | 120 |

Si deux protocoles annoncent la même destination, la route avec la **DA la plus basse** est choisie.

### 10.3 Routage statique

On configure manuellement les routes sur chaque routeur. Simple mais ne s'adapte pas automatiquement aux pannes.

**Syntaxe Cisco :**
```cisco
ip route [réseau_dest] [masque_dest] [next-hop_IP]
! ou
ip route [réseau_dest] [masque_dest] [interface_sortie]
```

**Exemple — 2 routeurs, 3 réseaux :**

```
PC1 (192.168.1.10) --- R1 --- [192.168.3.0/24] --- R2 --- PC2 (192.168.2.10)
```

Sur R1 :
```cisco
ip route 192.168.2.0 255.255.255.0 192.168.3.2
! "Pour atteindre 192.168.2.0, envoie à 192.168.3.2 (adresse de R2)"
```

Sur R2 :
```cisco
ip route 192.168.1.0 255.255.255.0 192.168.3.1
! "Pour atteindre 192.168.1.0, envoie à 192.168.3.1 (adresse de R1)"
```

**Route par défaut** (gateway of last resort) :
```cisco
ip route 0.0.0.0 0.0.0.0 192.168.1.254
! "Pour toute destination inconnue, envoie à 192.168.1.254"
```

---

## 11. Routage Dynamique : RIP et OSPF

### 11.1 Concepts communs

Le routage dynamique permet aux routeurs d'**échanger automatiquement leurs informations de routage** et de **recalculer les routes en cas de panne**. Plus adapté aux réseaux complexes ou évolutifs.

**Deux familles de protocoles :**
- **Distance-vector** : chaque routeur ne connaît que ses voisins et envoie sa table complète → simples mais convergence lente.
- **Link-state** : chaque routeur connaît la topologie complète du réseau → complexes mais convergence rapide.

### 11.2 RIP v2 (Routing Information Protocol)

**Type** : Distance-vector.  
**Métrique** : nombre de **sauts** (hop count).  
**Limite** : maximum **15 sauts** (16 = infini/inaccessible).  
**Distance administrative** : **120**.  
**Encapsulation** : UDP port 520.  
**Envoi des mises à jour** : toutes les 30 secondes en multicast `224.0.0.9`.

**Configuration Cisco :**
```cisco
router rip
 version 2
 no auto-summary          ! OBLIGATOIRE avec des masques différents (/16 et /24 mélangés)
 network 192.168.1.0      ! Active RIP sur toutes les interfaces de ce réseau
 network 10.1.0.0
```

**Signification des commandes :**

| Commande | Pourquoi |
|---|---|
| `version 2` | RIPv1 est classfull (ne supporte pas VLSM), v2 supporte les masques variables |
| `no auto-summary` | Empêche RIP de regrouper les routes par classe (indispensable en pratique) |
| `network X.X.X.X` | Annonce ce réseau et active RIP sur les interfaces correspondantes |

**Lecture des routes RIP :**
```
R    10.2.0.0/16 [120/1] via 10.1.0.2
```
- `R` = RIP
- `[120/1]` = DA=120, métrique=1 saut

### 11.3 OSPF (Open Shortest Path First)

**Type** : Link-state.  
**Métrique** : **coût** (inversement proportionnel à la bande passante : coût = 10⁸ / débit_bps).  
**Distance administrative** : **110**.  
**Encapsulation** : directement dans IP, protocole numéro **89**.  
**Base de données** : LSDB (Link State Database) = carte complète du réseau.  
**Zone obligatoire** : Area 0 (Backbone) — tous les routeurs doivent y être connectés.

**Coûts par défaut Cisco :**

| Interface | Bande passante | Coût OSPF |
|---|:-:|:-:|
| Serial (T1) | 1,544 Mbps | 64 |
| FastEthernet | 100 Mbps | 1 |
| GigabitEthernet | 1000 Mbps | 1 |

**Masque générique (wildcard)** : utilisé dans la commande `network` OSPF. C'est l'**inverse du masque réseau**.
- `/24` → wildcard `0.0.0.255` (les 8 bits hôte sont "libres")
- `/16` → wildcard `0.0.255.255`
- `/8` → wildcard `0.255.255.255`

**Configuration Cisco :**
```cisco
router ospf 1                           ! 1 = process-id (local au routeur)
 network 192.168.1.0 0.0.0.255 area 0
 network 10.1.0.0 0.0.255.255 area 0
```

**Lecture des routes OSPF :**
```
O    192.168.2.0/24 [110/129] via 10.1.0.2
```
- `O` = OSPF
- `[110/129]` = DA=110, coût=129 (64+64+1 = 2 liaisons série + 1 Ethernet)

### 11.4 RIP vs OSPF — Tableau comparatif

| Critère | RIP v2 | OSPF |
|---|---|---|
| Type | Distance-vector | Link-state |
| Métrique | Nombre de sauts | Coût (débit) |
| DA | 120 | 110 |
| Limite | 15 sauts | Aucune |
| Convergence | Lente | Rapide |
| Encapsulation | UDP port 520 | IP protocole 89 |
| Marqueur table routage | `R` | `O` |
| Zones | Non | Oui (Area 0 obligatoire) |
| Réseau conseillé | Très petits réseaux | Réseaux moyens/grands |
| Mise à jour | Toutes les 30s | Event-driven (uniquement si changement) |

**Si RIP et OSPF coexistent pour la même destination** → OSPF est choisi (DA 110 < DA 120).

### 11.5 Commandes de vérification

```cisco
show ip route                ! Table de routage complète
show ip protocols             ! Protocoles actifs et leurs paramètres
show ip ospf neighbor         ! Voisins OSPF établis
show ip rip database          ! Base de données RIP
show controllers Serial0/0/0  ! DCE ou DTE sur une liaison série
```

**Identifier le côté DCE** (où configurer le clock rate) :
```cisco
show controllers Serial0/0/0
! Si "DCE" apparaît → clock rate obligatoire ici
R1(config-if)# clock rate 128000
```

---

## 12. VLAN et Trunk 802.1Q

### 12.1 Définition et intérêt des VLANs

Un **VLAN** (Virtual Local Area Network) est une segmentation logique d'un réseau physique en plusieurs domaines de diffusion (broadcast domains) indépendants.

**Sans VLAN** : tous les équipements sur un switch partagent le même domaine de broadcast → tout broadcast (ARP, DHCP Discover) atteint tous les ports.

**Avec VLANs** : on crée des groupes logiques. Un broadcast d'un VLAN ne sort pas vers un autre VLAN.

**Avantages :**
- **Sécurité** : isolation du trafic (ex : VLAN Vidéosurveillance isolé du VLAN RH)
- **Performance** : réduction du trafic de broadcast
- **Flexibilité** : regroupement logique indépendant du câblage physique
- **Gestion** : simplification de l'administration

**VLAN par défaut** : VLAN 1 sur Cisco (tous les ports y appartiennent par défaut, non recommandé en production).

**ID VLAN** : 1 à 4094 (champ de 12 bits dans 802.1Q, 0 et 4095 réservés).

### 12.2 Types de ports

**Port d'accès (Access)** :
- Appartient à **un seul VLAN**
- Connecté à un équipement terminal (PC, imprimante, caméra)
- Les trames sont transmises **sans tag** vers le terminal
- Configuration : `switchport mode access` + `switchport access vlan [ID]`

**Port trunk** :
- Transporte le trafic de **plusieurs VLANs simultanément**
- Connecté à un autre switch ou un routeur
- Les trames sont **taguées** avec l'ID du VLAN (802.1Q)
- Configuration : `switchport mode trunk`

### 12.3 Standard IEEE 802.1Q (Dot1q)

Quand une trame traverse un lien trunk, un **tag de 4 octets** est inséré dans la trame Ethernet :

```
[MAC Dest | MAC Src | 0x8100 (TPID) | PCP (3b) + DEI (1b) + VID (12b) | EtherType | Données | CRC]
```

- **TPID** = `0x8100` : indique la présence d'un tag 802.1Q
- **VID** (VLAN ID) : 12 bits = identifiant du VLAN (0 à 4095)
- **PCP** (Priority Code Point) : 3 bits pour la QoS (IEEE 802.1p)

**VLAN natif** : VLAN dont les trames **ne sont pas taguées** sur un trunk. Par défaut = VLAN 1. Les deux extrémités d'un trunk doivent avoir le même VLAN natif configuré.

### 12.4 Configuration Cisco complète

**Création et nommage des VLANs :**
```cisco
SW1(config)# vlan 10
SW1(config-vlan)# name ADMIN
SW1(config-vlan)# exit
SW1(config)# vlan 20
SW1(config-vlan)# name PERSONNEL
SW1(config-vlan)# exit
```

**Assignation d'un port en mode accès :**
```cisco
SW1(config)# interface fastEthernet 0/1
SW1(config-if)# switchport mode access
SW1(config-if)# switchport access vlan 10
SW1(config-if)# no shutdown
SW1(config-if)# exit
```

**Configuration d'un port trunk :**
```cisco
SW1(config)# interface gigabitEthernet 0/1
SW1(config-if)# switchport mode trunk
SW1(config-if)# switchport trunk native vlan 1
SW1(config-if)# no shutdown
SW1(config-if)# exit
```

**Vérifications :**
```cisco
SW1# show vlan brief              ! Liste des VLANs et leurs ports
SW1# show interfaces trunk        ! Liens trunk actifs et VLANs autorisés
SW1# show mac address-table       ! Table MAC
```

### 12.5 VTP (VLAN Trunking Protocol)

Protocole Cisco propriétaire permettant de **propager la base de données VLAN** d'un switch serveur vers les switchs clients sur les liens trunk. Évite de reconfigurer manuellement les VLANs sur chaque switch.

---

## 13. Routage Inter-VLAN (Router-on-a-Stick)

### 13.1 Problématique

Les VLANs sont des domaines de broadcast **isolés**. Pour qu'un hôte du VLAN 10 communique avec un hôte du VLAN 20, il faut **un équipement de couche 3** (routeur ou switch L3).

### 13.2 Méthode Router-on-a-Stick

Un seul câble physique entre le switch et le routeur, configuré en **trunk** côté switch. Le routeur crée des **sous-interfaces** (subinterfaces) logiques, une par VLAN.

```
[PC VLAN10] --- [SW trunk] ---(1 câble physique)--- [Routeur R1]
[PC VLAN20] ---[         ]                            |- Gi0/0.10 → VLAN 10
                                                      |- Gi0/0.20 → VLAN 20
```

### 13.3 Configuration

**Côté Switch — lien vers routeur en trunk :**
```cisco
interface gigabitEthernet 0/1
 switchport mode trunk
 no shutdown
```

**Côté Routeur — sous-interfaces :**
```cisco
! Activer l'interface physique sans IP
interface gigabitEthernet 0/0
 no shutdown
 exit

! Sous-interface VLAN 10
interface gigabitEthernet 0/0.10
 encapsulation dot1Q 10           ! Tagger les trames avec VID=10
 ip address 192.168.10.254 255.255.255.0
 exit

! Sous-interface VLAN 20
interface gigabitEthernet 0/0.20
 encapsulation dot1Q 20
 ip address 192.168.20.254 255.255.255.0
 exit

! Sous-interface VLAN 30
interface gigabitEthernet 0/0.30
 encapsulation dot1Q 30
 ip address 192.168.30.254 255.255.255.0
 exit
```

**Sur les PC clients** : configurer la passerelle = l'IP de la sous-interface correspondant à leur VLAN.

**Infrastructure complète SAE 1.02 :**

| VLAN | Nom | Réseau | Passerelle |
|:-:|---|---|---|
| 10 | ADMIN | 192.168.10.0/24 | 192.168.10.254 |
| 20 | PERSONNEL | 192.168.20.0/24 | 192.168.20.254 |
| 30 | PRODUCTION | 192.168.30.0/24 | 192.168.30.254 |
| 40 | VIDEO | 192.168.40.0/24 | 192.168.40.254 |
| 800 | INTERNET | 192.168.100.0/24 | 192.168.100.254 |

---

## 14. Spanning Tree Protocol (STP)

### 14.1 Problème des boucles de niveau 2

Si un réseau commétatif possède des **chemins redondants** (pour la tolérance aux pannes), cela crée des boucles au niveau 2. Une boucle L2 provoque :
- Des **tempêtes de broadcast** (une trame de broadcast se reproduit indéfiniment)
- La **multiplication des frames** dans la table MAC
- La **saturation** du réseau en quelques secondes

### 14.2 Fonctionnement de STP (IEEE 802.1D)

STP bloque **logiquement** certains ports pour éliminer les boucles, tout en conservant la redondance physique. Si un lien actif tombe, STP réactive le port bloqué.

**Élection du Root Bridge :**
1. Chaque switch a un **Bridge ID (BID)** = Priorité (2 octets, par défaut 32768) + Adresse MAC (6 octets)
2. Le switch avec le **BID le plus bas** est élu Root Bridge
3. Pour forcer un switch à devenir Root Bridge → diminuer sa priorité (valeur multiple de 4096)

**Rôles des ports :**

| Rôle | Description |
|---|---|
| **Root Port (RP)** | Port offrant le chemin le plus court vers le Root Bridge. Un par switch non-root. |
| **Designated Port (DP)** | Port responsable de la transmission sur un segment. Un par segment. |
| **Blocked Port (BP)** | Port bloqué logiquement pour rompre la boucle. Ne transmet pas de données. |

**Coûts de liens (802.1D) :**

| Débit | Coût |
|:-:|:-:|
| 10 Mbps | 100 |
| 100 Mbps | 19 |
| 1 Gbps | 4 |
| 10 Gbps | 2 |

**Messages BPDUs** (Bridge Protocol Data Units) : messages échangés entre switches pour l'élection et la maintenance de l'arbre.

**PVST+** (Per-VLAN Spanning Tree Plus) : variante Cisco qui crée une instance STP par VLAN.

**RSTP** (IEEE 802.1w) : version rapide, convergence quasi-instantanée (secondes vs 30-50s pour 802.1D).

### 14.3 Commandes Cisco

```cisco
! Afficher l'état STP
SW1# show spanning-tree
SW1# show spanning-tree summary

! Forcer ce switch à devenir Root Bridge pour le VLAN 10
SW1(config)# spanning-tree vlan 10 priority 4096
! ou commande automatique
SW1(config)# spanning-tree vlan 10 root primary
```

---

## 15. EtherChannel

### 15.1 Principe

L'**EtherChannel** (agrégation de liens / LAG) regroupe plusieurs **liens physiques parallèles** entre deux switches en un **seul lien logique**. Cela permet d'augmenter la bande passante et d'assurer la redondance.

**Avantages :**
- Augmentation du débit (jusqu'à 8 liens × débit unitaire)
- Tolérance aux pannes : si un lien physique tombe, l'EtherChannel reste actif
- STP voit un seul lien logique → pas de port bloqué

**Maximum** : 8 ports physiques par EtherChannel.

### 15.2 Protocoles de négociation

| Protocole | Standard | Mode actif | Mode passif |
|---|---|---|---|
| **LACP** (Link Aggregation Control Protocol) | IEEE 802.3ad | `active` | `passive` |
| **PAgP** (Port Aggregation Protocol) | Cisco propriétaire | `desirable` | `auto` |
| Mode **On** | Manuel | Sans protocole | — |

**Règle** : les deux extrémités doivent utiliser le même protocole. Le mode `On` force sans négociation.

### 15.3 Configuration Cisco

```cisco
! Configurer les 2 interfaces physiques ensemble
SW1(config)# interface range gigabitEthernet 0/1 - 2
SW1(config-if-range)# switchport mode trunk
SW1(config-if-range)# channel-group 1 mode active    ! LACP actif
SW1(config-if-range)# no shutdown

! Vérification
SW1# show etherchannel summary
SW1# show etherchannel 1 detail
```

---

## 16. Passerelle Linux (NAT & IP Forwarding)

### 16.1 Architecture

Une **passerelle Linux** est une machine Linux avec **deux interfaces réseau** :
- **Interface WAN** (`enp0s3`) : connectée au réseau externe (IUT, Internet)
- **Interface LAN** (`enp0s8`) : connectée au réseau interne privé

```
[H1 192.168.0.2] ──┐
[H2 192.168.0.3] ──┤─── [enp0s8:192.168.0.1 | GATEWAY | enp0s3:172.31.x.x] ──── [IUT / Internet]
[H3 192.168.0.4] ──┘
```

**Deux fonctions essentielles :**
1. **IP Forwarding** : autoriser le noyau Linux à relayer les paquets entre les deux interfaces
2. **NAT Masquerade** : remplacer les adresses IP privées par l'adresse IP publique de la passerelle (SNAT)

### 16.2 IP Forwarding

Par défaut, Linux **jette** les paquets qui ne lui sont pas destinés. L'IP Forwarding lui indique de les retransmettre.

**Vérification :**
```bash
cat /proc/sys/net/ipv4/ip_forward
# 0 = désactivé, 1 = activé
```

**Activation immédiate (non persistante) :**
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
# ou
sudo sysctl -w net.ipv4.ip_forward=1
```

**Activation permanente** (survit au redémarrage) — éditer `/etc/sysctl.conf` :
```text
net.ipv4.ip_forward=1
```
Puis appliquer :
```bash
sudo sysctl -p
```

### 16.3 NAT Masquerade (iptables)

**Pourquoi le NAT est nécessaire ?**

Sans NAT, H1 envoie un paquet vers l'extérieur avec l'IP source `192.168.0.2` (privée, non routable). Le routeur distant ne sait pas où répondre → le paquet est perdu.

Avec NAT **MASQUERADE**, la passerelle :
1. Intercepte le paquet sortant
2. **Remplace l'IP source** `192.168.0.2` par sa propre IP `172.31.x.x`
3. Mémorise la correspondance dans la table de traduction (NAT table)
4. Quand la réponse arrive, **réécrit** l'IP destination avec `192.168.0.2` et retransmet à H1

**Commande iptables :**
```bash
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
# -t nat       : table NAT
# -A POSTROUTING : après la décision de routage
# -o enp0s3    : sur les paquets sortant par l'interface WAN
# -j MASQUERADE : appliquer le masquage d'adresse
```

**Vérification des règles NAT :**
```bash
sudo iptables -t nat -L -v -n
```

### 16.4 Configuration des interfaces

**Sur la passerelle :**
```bash
# Interface interne (LAN) — IP statique
sudo ip a add 192.168.0.1/24 dev enp0s8
sudo ip link set dev enp0s8 up

# Interface externe (WAN) — via DHCP si réseau IUT
sudo dhclient enp0s3

# Vérification
ip -4 -br a    # Vue compacte de toutes les IPs
```

**Sur les clients H1, H2 :**
```bash
sudo ip a add 192.168.0.2/24 dev enp0s3
sudo ip link set dev enp0s3 up
sudo ip route add default via 192.168.0.1    # Passerelle par défaut
```

**Sur H3 (Windows) :** IP : `192.168.0.4` | Masque : `255.255.255.0` | Passerelle : `192.168.0.1`  
⚠️ Windows bloque les pings par défaut → activer via Pare-feu > Partage de fichiers et d'imprimantes.

### 16.5 Configuration DNS sur les clients

ans /etc:resolv.conf mettre :
```bash
search univ-artois.fr
nameserver 172.18.26.101
nameserver 172.18.26.102
```
*Tests :*
```bash
nslookup iut-rt                     # doit résoudre l'IP de iut-rt
ping iut-rt                         # doit répondre
```

### 🌍 15.6. Configurer le proxy pour accéder à Internet
> [!WARNING]
> Sans proxy, impossible d'aller sur Internet. L'université impose un proxy pour toutes les connexions sortantes.

**Dans Firefox (H1 ou H2) :**
Préférences > Réseau > Configuration manuelle du proxy :
*   **Proxy HTTP :** `cache-etu.univ-artois.fr`
*   **Port :** `3128`
*   **also use this proxy for https :** cochée
*   **No proxy for :** `iut-rt, 172.31.25.9`

*Test final : Naviguer vers `https://www.wikipedia.org` => Doit s'afficher.*


### 16.7 Protocole de validation

| Étape | Commande | Résultat attendu |
|---|---|---|
| 1. Connectivité locale | `ping 192.168.0.1` | OK (passerelle) |
| 2. Connectivité entre clients | `ping 192.168.0.3` | OK (H2) |
| 3. Connectivité WAN | `ping 172.31.25.9` | OK après NAT |
| 4. Vérifier le saut | `traceroute 8.8.8.8` | 1er saut = 192.168.0.1 |
| 5. DNS | `nslookup iut-rt` | Résout correctement |

### 16.7 Résolution de problèmes courants

| Symptôme | Cause probable | Solution |
|---|---|---|
| Pas de route vers l'extérieur | Route par défaut manquante | `ip route add default via 192.168.0.1` |
| Host unreachable sur passerelle | IP Forwarding = 0 | `echo 1 > /proc/sys/net/ipv4/ip_forward` |
| Ping OK, web KO | DNS non configuré | Modifier `/etc/resolv.conf` |
| Ping Windows bloqué | Pare-feu Windows | Activer règle ICMP entrant |

### 16.8 NAT/PAT Cisco — Traduction d'adresses

Le NAT sur routeur Cisco translate des adresses privées (inside) vers des adresses publiques (outside). Trois variantes existent, à choisir selon le besoin.

**Vocabulaire Cisco NAT :**

| Terme | Signification |
|---|---|
| **inside local** | IP privée d'un hôte interne |
| **inside global** | IP publique vue de l'extérieur |
| **outside local** | IP destination vue de l'intérieur |
| **outside global** | IP publique de la destination réelle |

**NAT Statique** — une IP privée ↔ une IP publique fixe (exposer un serveur) :
```cisco
ip nat inside source static 192.168.1.10 203.0.113.10

interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.0
 ip nat outside

interface GigabitEthernet0/1
 ip address 192.168.1.254 255.255.255.0
 ip nat inside
```

**NAT Dynamique** — pool d'adresses publiques :
```cisco
ip nat pool PUBLIC_POOL 203.0.113.10 203.0.113.20 netmask 255.255.255.0
access-list 1 permit 192.168.1.0 0.0.0.255
ip nat inside source list 1 pool PUBLIC_POOL
```

**PAT / NAT Overload** — toute une plage → une seule IP publique (cas le plus courant) :
```cisco
access-list 1 permit 192.168.0.0 0.0.0.255
ip nat inside source list 1 interface GigabitEthernet0/0 overload
```

**Vérification :**
```cisco
show ip nat translations        ! Table de traduction active
show ip nat statistics           ! Compteurs hits/misses
clear ip nat translation *       ! Vider la table (test)
```

**Différence Linux / Cisco :**

| Aspect | Linux (iptables) | Cisco IOS |
|---|---|---|
| Commande | `iptables -t nat -j MASQUERADE` | `ip nat inside source list … overload` |
| Persistance | `/etc/sysctl.conf` + script | NVRAM (sauvegarde auto) |
| Granularité | Par interface / règle | Par ACL / pool |

---

## 17. Filtrage Réseau Linux (iptables & nftables)

### 17.1 Architecture Netfilter

**Netfilter** est le sous-système du noyau Linux qui intercepte et traite les paquets réseau. `iptables` et `nftables` sont les interfaces en espace utilisateur pour configurer ses règles.

**Points d'accroche (hooks) dans le chemin des paquets :**

```
Réseau ──► [PREROUTING] ──► [INPUT] ──► Processus local
                        ↘
                       [FORWARD]
                        ↗
Réseau ◄── [POSTROUTING] ◄── [OUTPUT] ◄── Processus local
```

**Les trois chaînes principales :**

| Chaîne | Paquets concernés | Usage typique |
|---|---|---|
| **INPUT** | Destinés à la machine locale | Protéger la machine elle-même |
| **OUTPUT** | Générés par la machine locale | Contrôler les sorties |
| **FORWARD** | Transitent par la machine (routage) | Pare-feu passerelle |

**Les tables iptables :**

| Table | Rôle |
|---|---|
| **filter** | Filtrage (ACCEPT / DROP / REJECT) — par défaut |
| **nat** | Traduction d'adresses (MASQUERADE, DNAT, SNAT) |
| **mangle** | Modification des champs IP (TTL, TOS…) |

### 17.2 Syntaxe iptables

```bash
iptables [-t TABLE] -A|-I|-D CHAINE [critères] -j CIBLE
#
# -t filter          : table (optionnel, filter par défaut)
# -A INPUT           : Append — ajouter en fin de chaîne
# -I INPUT 1         : Insert — insérer en position 1
# -D INPUT 3         : Delete — supprimer la règle n°3
# -p tcp             : protocole (tcp, udp, icmp)
# --dport 22         : port destination
# --sport 1024:65535 : plage de ports sources
# -s 192.168.0.0/24  : adresse source
# -d 10.0.0.1        : adresse destination
# -i eth0            : interface entrante
# -o eth1            : interface sortante
# -j ACCEPT|DROP|REJECT|LOG : cible
```

**Cibles principales :**

| Cible | Comportement | Note |
|---|---|---|
| **ACCEPT** | Laisser passer | — |
| **DROP** | Jeter silencieusement | L'expéditeur ne reçoit aucune réponse |
| **REJECT** | Refuser avec notification ICMP | L'expéditeur reçoit "port unreachable" |
| **LOG** | Journaliser et continuer | Doit être suivi d'une règle DROP ou ACCEPT |

> **DROP vs REJECT** : `DROP` est invisible — adapté contre les scanners. `REJECT` est courtois — adapté en réseau interne où le client doit comprendre le refus.

### 17.3 Politique par défaut et exemples pratiques

**Stratégie "tout fermer, puis ouvrir" :**
```bash
# Politique par défaut : tout bloquer en entrée et transit
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Loopback (indispensable)
sudo iptables -A INPUT -i lo -j ACCEPT

# Connexions établies / liées (stateful)
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# HTTP / HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP (pings)
sudo iptables -A INPUT -p icmp -j ACCEPT
```

**Chaîne personnalisée :**
```bash
sudo iptables -N SCAN_FILTER
sudo iptables -A SCAN_FILTER -p tcp --tcp-flags ALL NONE -j DROP   # NULL scan
sudo iptables -A SCAN_FILTER -p tcp --tcp-flags ALL ALL -j DROP    # XMAS scan
sudo iptables -A INPUT -j SCAN_FILTER
```

**Journalisation avant blocage :**
```bash
sudo iptables -A INPUT -p tcp --dport 23 -j LOG --log-prefix "TELNET-BLOCKED: " --log-level 4
sudo iptables -A INPUT -p tcp --dport 23 -j DROP
```

### 17.4 Commandes de gestion

```bash
sudo iptables -L -v -n --line-numbers   # Lister avec numéros
sudo iptables -F                         # Flush — supprimer toutes les règles
sudo iptables -P INPUT ACCEPT            # Reset politique (avant flush total)
sudo iptables-save > /etc/iptables/rules.v4    # Sauvegarder
sudo iptables-restore < /etc/iptables/rules.v4 # Restaurer
```

### 17.5 nftables — Le successeur moderne

**nftables** remplace iptables depuis Linux 3.13 (défaut Debian 10+). Syntaxe plus lisible, performances améliorées (sets kernel-space).

**Script nftables type (pare-feu passerelle) :**
```bash
#!/usr/sbin/nft -f
flush ruleset

table ip filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        ct state established,related accept
        ip protocol icmp accept
        tcp dport 22 accept
        tcp dport { 80, 443 } accept
        log prefix "nft-DROP: " drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

**Ensembles (blacklists dynamiques) :**
```bash
nft add set ip filter BLACKLIST { type ipv4_addr; }
nft add element ip filter BLACKLIST { 203.0.113.50, 198.51.100.0/24 }
nft add rule ip filter input ip saddr @BLACKLIST drop
```

**Comparaison rapide :**

| Aspect | iptables | nftables |
|---|---|---|
| Syntaxe | `iptables -A INPUT -p tcp --dport 22 -j ACCEPT` | `tcp dport 22 accept` |
| Organisation | Tables séparées (filter, nat, mangle) | Un seul fichier structuré |
| Performances | Règle par règle | Sets en espace noyau |
| Statut | Legacy (maintenu) | Recommandé Debian 10+ |

---

## 18. ACL — Listes de Contrôle d'Accès

### 17.1 Principe

Les ACL (Access Control Lists) sont des **listes de règles de filtrage** configurées sur les interfaces d'un routeur Cisco. Elles permettent d'autoriser ou refuser le trafic selon divers critères.

**Règle implicite finale** : toute ACL se termine par un `deny any` implicite. **Si une ACL ne contient pas de `permit any`, tout ce qui ne correspond à aucune règle explicite sera bloqué.**

**Traitement** : les règles sont évaluées dans l'ordre, de haut en bas. Dès qu'une règle correspond, elle est appliquée et l'évaluation s'arrête.

### 17.2 ACL Standard (numéros 1–99)

**Filtre uniquement sur l'IP source.**

**Placement** : **au plus près de la destination** (car elle manque de précision — elle bloquerait tout le trafic de la source vers n'importe quelle destination si placée près de la source).

```cisco
! Bloquer un hôte spécifique
access-list 1 deny host 192.168.3.20
access-list 1 permit any              ! OBLIGATOIRE pour ne pas tout bloquer

! Bloquer tout un sous-réseau (wildcard = inverse du masque)
access-list 1 deny 192.168.3.0 0.0.0.255
access-list 1 permit any

! Appliquer sur l'interface (OUT = sortie vers la destination)
interface fa0/0
 ip access-group 1 out
```

**Masque générique (wildcard)** : 
- `host 192.168.3.20` = un seul hôte = `192.168.3.20 0.0.0.0`
- `192.168.3.0 0.0.0.255` = tout le sous-réseau `/24`
- `any` = toute adresse = `0.0.0.0 255.255.255.255`

### 17.3 ACL Étendue (numéros 100–199)

**Filtre sur : source, destination, protocole, port.**

**Placement** : **au plus près de la source** (car sa précision permet de bloquer dès l'origine, économisant de la bande passante).

```cisco
! Syntaxe :
access-list [100-199] [permit|deny] [protocole] [src + wildcard] [dest + wildcard] [opérateur port]

! Exemples :
! Autoriser HTTP (TCP port 80) du LAN Belgique vers le serveur web
access-list 100 permit tcp 192.168.3.0 0.0.0.255 host 192.168.1.254 eq 80

! Autoriser le ping (ICMP echo) du LAN Belgique vers le serveur
access-list 100 permit icmp 192.168.3.0 0.0.0.255 host 192.168.1.254 echo

! Appliquer sur l'interface côté source (IN = entrée depuis le LAN)
interface fa0/1
 ip access-group 100 in
```

**Opérateurs de port :**

| Opérateur | Signification |
|:-:|---|
| `eq 80` | Égal au port 80 |
| `gt 1023` | Supérieur au port 1023 |
| `lt 1024` | Inférieur au port 1024 |
| `range 20 21` | Entre les ports 20 et 21 |

### 17.4 Gestion des ACL nommées

```cisco
! ACL standard nommée (plus lisible)
ip access-list standard BLOQUER_PC3
 deny host 192.168.3.20
 permit any

! Modifier une règle (supprimer la règle numéro 10)
ip access-list standard 1
 no 10
 10 deny 192.168.3.0 0.0.0.255

! Voir les ACL
show access-lists
show ip interface fa0/0    ! voir quelles ACL sont appliquées
```

### 17.5 Résumé des règles de placement

| Type ACL | Filtre | Placement |
|---|---|---|
| Standard (1-99) | IP source seulement | **Près de la destination** |
| Étendue (100-199) | Source + destination + protocole + port | **Près de la source** |

---

## 19. La Virtualisation

### 18.1 Concepts fondamentaux

La **virtualisation** consiste à créer une couche d'abstraction logicielle entre le matériel physique et les systèmes d'exploitation. Une seule machine physique peut ainsi héberger plusieurs **machines virtuelles (VM)** complètement isolées.

**Avantages :**
- **Consolidation** : réduire le nombre de serveurs physiques (et donc les coûts et la consommation électrique)
- **Isolation** : chaque VM est indépendante — une VM en panne n'affecte pas les autres
- **Snapshots** : sauvegarder l'état complet d'une VM à un instant T pour une restauration rapide
- **Migration à chaud (Live Migration)** : déplacer une VM d'un hôte physique à un autre sans interruption de service
- **Environnements de test** : créer/supprimer des environnements en quelques secondes

**Terminologie :**

| Terme | Définition |
|---|---|
| **Hôte (Host)** | La machine physique qui héberge les VMs |
| **Invité (Guest)** | La VM — elle croit être sur du matériel dédié |
| **Hyperviseur** | Le logiciel qui virtualise le matériel et répartit les ressources |
| **VM (Machine Virtuelle)** | Émulation complète d'un ordinateur (CPU, RAM, disque, réseau) |
| **Template / Image** | Modèle de VM à partir duquel on clone de nouvelles instances |
| **Snapshot** | Capture de l'état d'une VM (disque + RAM + config) à un instant T |

---

### 18.2 Types d'hyperviseurs

| Type | Description | Exemples |
|---|---|---|
| **Type 1 (Bare-metal)** | S'installe directement sur le matériel, sans OS hôte. Plus performant, utilisé en production. | VMware ESXi, Proxmox VE, Microsoft Hyper-V |
| **Type 2 (Hosted)** | S'installe comme une application dans un OS hôte. Plus simple, utilisé pour le test/dev. | VirtualBox (Oracle), VMware Workstation |

```
Type 1 :                          Type 2 :
┌──────────────┐                 ┌──────────────────┐
│   VM1  │ VM2 │                 │   VM1  │   VM2   │
├──────────────┤                 ├──────────────────┤
│  Hyperviseur │                 │   Hyperviseur    │
├──────────────┤                 ├──────────────────┤
│   Matériel   │                 │    OS Hôte       │
└──────────────┘                 ├──────────────────┤
                                 │    Matériel      │
                                 └──────────────────┘
```

---

### 18.3 Modes réseau d'une VM

| Mode | Comportement | Usage |
|---|---|---|
| **NAT** | La VM partage l'IP de l'hôte. Elle accède à Internet mais n'est pas joignable de l'extérieur. | Usage courant, simple |
| **Bridge (Pont)** | La VM obtient une IP du même réseau que l'hôte (DHCP ou statique). Elle est directement visible sur le LAN. | Production, accès réseau réel |
| **Réseau interne** | Communication uniquement entre VMs du même réseau interne. Pas d'accès à l'hôte ni à Internet. | TP, isolation totale |
| **Host-Only** | La VM communique uniquement avec l'hôte. | Développement local |

---

### 18.4 Conteneurisation — Docker

Les **conteneurs** ne virtualisent pas le matériel mais **partagent le noyau (kernel)** de l'OS hôte. Ils sont plus légers et démarrent en millisecondes.

**VM vs Conteneur :**

| Critère | Machine Virtuelle | Conteneur Docker |
|---|---|---|
| Isolation | OS complet isolé | Processus isolés, kernel partagé |
| Démarrage | Minutes | Secondes / millisecondes |
| Taille | Gigaoctets | Mégaoctets |
| Performance | Overhead hyperviseur | Proche du natif |
| Usage | Virtualisation complète | Déploiement d'applications |

**Vocabulaire Docker :**

| Terme | Définition |
|---|---|
| **Image** | Modèle immuable (lecture seule) d'un conteneur. Stockée dans un registre (Docker Hub). |
| **Conteneur** | Instance en cours d'exécution d'une image |
| **Dockerfile** | Fichier texte décrivant comment construire une image |
| **Registre** | Serveur de stockage d'images (Docker Hub, GitLab Registry) |
| **Volume** | Répertoire persistant monté dans un conteneur |

**Commandes Docker essentielles :**

```bash
# Gestion des images
docker pull ubuntu:22.04          # Télécharger une image
docker images                      # Lister les images locales
docker rmi ubuntu:22.04           # Supprimer une image

# Gestion des conteneurs
docker run -it ubuntu:22.04 bash   # Créer et démarrer un conteneur interactif
docker run -d -p 8080:80 nginx     # Démarrer en arrière-plan (port hôte:port VM)
docker ps                          # Conteneurs actifs
docker ps -a                       # Tous les conteneurs (y compris arrêtés)
docker stop <id>                   # Arrêter un conteneur
docker rm <id>                     # Supprimer un conteneur

# Construction
docker build -t monapp:1.0 .       # Construire une image depuis un Dockerfile

# Réseau
docker network ls                  # Lister les réseaux Docker
docker network create monreseau    # Créer un réseau personnalisé
```

**Exemple de Dockerfile :**
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y apache2
COPY ./site /var/www/html/
EXPOSE 80
CMD ["apache2ctl", "-D", "FOREGROUND"]
```

---

## 20. Les Clusters et la Haute Disponibilité

### 19.1 Concepts

La **haute disponibilité (HA — High Availability)** désigne la capacité d'un système à rester opérationnel malgré la défaillance d'un ou plusieurs composants.

**Métriques clés :**

| Métrique | Définition | Exemple |
|---|---|---|
| **Disponibilité** | % du temps où le service est opérationnel | 99,9% = 8,76h d'arrêt/an |
| **RPO** (Recovery Point Objective) | Perte de données maximale tolérée | "Pas plus de 1h de données perdues" |
| **RTO** (Recovery Time Objective) | Durée maximale de remise en service | "Service restauré en moins de 30 min" |
| **SLA** (Service Level Agreement) | Contrat de niveau de service avec le client | "99,95% de disponibilité garantie" |

**Niveaux de disponibilité :**

| Disponibilité | Indisponibilité/an | Qualification |
|:-:|---|---|
| 99% | ~88 heures | Standard |
| 99,9% (three nines) | ~8,76 heures | Haute disponibilité |
| 99,99% (four nines) | ~52 minutes | Très haute disponibilité |
| 99,999% (five nines) | ~5 minutes | Critique (télécoms, banques) |

---

### 19.2 Architectures de cluster

**Actif-Passif (Failover) :**

Un serveur **actif** traite toutes les requêtes. Un serveur **passif** surveille l'actif et prend le relais automatiquement si celui-ci tombe (**bascule / failover**). Une **VIP (Virtual IP)** est l'adresse IP flottante qui "suit" le nœud actif.

```
Clients → [VIP: 10.0.0.100]
              │
    ┌─────────┴─────────┐
    │ Actif (Nœud 1)    │ Passif (Nœud 2) — surveille via heartbeat
    │ 10.0.0.101        │ 10.0.0.102
    └───────────────────┘
    ← En cas de panne du nœud 1, la VIP bascule sur le nœud 2 →
```

**Actif-Actif (Load Balancing) :**

Tous les nœuds traitent des requêtes simultanément. Un **load balancer** distribue la charge. Si un nœud tombe, les autres absorbent son trafic.

```
Clients → [Load Balancer]
              │
    ┌─────────┼─────────┐
    │         │         │
 Nœud 1   Nœud 2   Nœud 3
```

**Algorithmes de répartition de charge :**

| Algorithme | Description |
|---|---|
| **Round Robin** | Distribution séquentielle (1→2→3→1→2→3...) |
| **Least Connections** | Vers le serveur ayant le moins de connexions actives |
| **IP Hash** | Basé sur l'IP source — même client → même serveur (persistance de session) |
| **Weighted Round Robin** | Pondération selon la capacité du serveur |

---

### 19.3 Scalabilité

| Type | Description | Exemple |
|---|---|---|
| **Scalabilité verticale (Scale-up)** | Augmenter les ressources d'un seul serveur (plus de RAM, CPU plus puissant) | Passer de 16 à 64 Go de RAM |
| **Scalabilité horizontale (Scale-out)** | Ajouter des serveurs au cluster | Passer de 3 à 10 nœuds web |

La scalabilité horizontale est préférée pour les architectures cloud-native car elle permet de s'adapter dynamiquement à la charge.

---

### 19.4 Outils et protocoles

**VRRP (Virtual Router Redundancy Protocol)** : protocole standard (RFC 5798) permettant à plusieurs routeurs de partager une adresse IP virtuelle. Un **Master** détient la VIP, les **Backup** écoutent. Si le Master disparaît, le Backup avec la priorité la plus haute prend la VIP.

**Keepalived** : implémentation Linux de VRRP, couramment utilisée pour la HA de routeurs ou de load balancers (HAProxy).

**HAProxy** : load balancer et proxy TCP/HTTP open-source très performant. Gère le health-checking automatique des serveurs backend.

```
# Exemple de configuration HAProxy (load balancer HTTP)
frontend http_front
    bind *:80
    default_backend http_back

backend http_back
    balance roundrobin
    option httpchk GET /health
    server web1 192.168.1.10:80 check
    server web2 192.168.1.11:80 check
    server web3 192.168.1.12:80 check
```

---

## 21. Le Cloud et le Green Computing

### 20.1 Modèles de service

Le cloud computing consiste à **louer des ressources informatiques à la demande** sur Internet, sans avoir à gérer l'infrastructure physique.

| Modèle | Acronyme | Ce que fournit le fournisseur | Ce que gère le client | Exemple |
|---|:-:|---|---|---|
| **Infrastructure as a Service** | IaaS | Matériel virtualisé (CPU, RAM, stockage, réseau) | OS, middleware, applications | AWS EC2, Azure VMs, GCP Compute Engine |
| **Platform as a Service** | PaaS | IaaS + OS + runtime + middleware | Applications et données | Heroku, Google App Engine, Azure App Service |
| **Software as a Service** | SaaS | Tout — application complète prête à l'emploi | Uniquement les données/config | Gmail, Salesforce, Microsoft 365 |

```
Responsabilités croissantes du fournisseur →
┌──────────────────────────────────────────────┐
│         SaaS — Application fournie           │
├──────────────────────────────────────────────┤
│     PaaS — Runtime + middleware fournis      │
├──────────────────────────────────────────────┤
│  IaaS — Infrastructure virtuelle fournie     │
├──────────────────────────────────────────────┤
│    On-Premise — Tout géré en interne         │
└──────────────────────────────────────────────┘
```

---

### 20.2 Modèles de déploiement

| Modèle | Description | Usage |
|---|---|---|
| **Cloud public** | Ressources partagées chez un fournisseur tiers (AWS, Azure, GCP). Facturation à l'usage. | Start-ups, PME, projets variables |
| **Cloud privé** | Infrastructure cloud dédiée à une seule organisation (on-premise ou hébergée). | Données sensibles, banques, santé |
| **Cloud hybride** | Combinaison de cloud public et privé — données sensibles en privé, charge variable en public. | Entreprises avec contraintes réglementaires |
| **Multi-cloud** | Utiliser plusieurs fournisseurs cloud publics simultanément pour éviter la dépendance (vendor lock-in). | Grandes entreprises |

---

### 20.3 Principaux fournisseurs

| Fournisseur | Nom complet | Part de marché | Services phares |
|---|---|:-:|---|
| **AWS** | Amazon Web Services | ~32% | EC2 (VM), S3 (stockage), Lambda (serverless), RDS |
| **Azure** | Microsoft Azure | ~22% | VMs, Active Directory, Teams, Office 365 |
| **GCP** | Google Cloud Platform | ~11% | BigQuery (analytics), Kubernetes (GKE), TensorFlow |

**Services cloud courants :**

| Type | Service | Description |
|---|---|---|
| Calcul | VM, Conteneurs, Serverless | Exécution de code |
| Stockage | Objet (S3), Bloc (EBS), Fichier (NFS) | Persistance des données |
| Réseau | VPC, CDN, Load Balancer, DNS | Connectivité |
| Base de données | SQL géré, NoSQL, Cache (Redis) | Données structurées/non-structurées |
| Sécurité | IAM, WAF, Chiffrement | Contrôle d'accès, protection |

---

### 20.4 Green Computing

Le **Green Computing** vise à réduire l'empreinte environnementale de l'informatique.

**Indicateur clé — PUE (Power Usage Effectiveness) :**

$$\text{PUE} = \frac{\text{Énergie totale du datacenter}}{\text{Énergie consommée par les équipements IT}}$$

- **PUE = 1,0** : efficacité parfaite (toute l'énergie va aux serveurs, zéro gaspillage)
- **PUE = 2,0** : 50% de l'énergie est gaspillée en climatisation, éclairage, etc.
- **Objectif** : PUE < 1,5 (bons datacenters atteignent 1,1 – 1,2)

**Leviers du Green Computing :**

| Levier | Description |
|---|---|
| **Mutualisation / Consolidation** | Remplacer 10 serveurs peu utilisés par 1 serveur puissant virtualisé |
| **Refroidissement efficient** | Free cooling (air extérieur), refroidissement liquide, immersion cooling |
| **Énergies renouvelables** | Alimentation par solaire, éolien, hydroélectrique |
| **Efficacité des équipements** | Alimentation à rendement élevé (80 Plus), processeurs basse consommation |
| **Durée de vie** | Prolonger la vie des équipements, éviter l'obsolescence programmée |
| **Localisation géographique** | Installer les datacenters dans des pays froids (Islande, pays nordiques) |

**Chiffres clés :**
- Le numérique représente environ **4%** des émissions mondiales de CO₂ (en croissance)
- Un datacenter moyen consomme autant d'électricité qu'une ville de 50 000 habitants
- La virtualisation peut réduire le parc de serveurs d'un facteur 10:1

---

## 22. Serveurs Web : Apache2 et Nginx

### 21.1 Apache2

**Installation :**
```bash
sudo apt update
sudo apt install apache2 -y
sudo systemctl status apache2    # Vérifier : Active (running)
```

**Structure des fichiers de configuration :**
- Sites disponibles : `/etc/apache2/sites-available/`
- Sites activés (liens symboliques) : `/etc/apache2/sites-enabled/`
- Modules : `sudo a2enmod [module]`
- Activer un site : `sudo a2ensite [site].conf`
- Désactiver : `sudo a2dissite [site].conf`
- Racine web par défaut : `/var/www/html/`

**Configuration d'un Virtual Host :**
```apache
# /etc/apache2/sites-available/vendeur.conf
<VirtualHost *:80>
    ServerName vendeur.localhost
    DocumentRoot /var/www/vendeur
    ErrorLog ${APACHE_LOG_DIR}/vendeur_error.log
    CustomLog ${APACHE_LOG_DIR}/vendeur_access.log combined
</VirtualHost>
```

**Authentification par groupe :**
```bash
sudo a2enmod authz_groupfile
sudo htpasswd -c /etc/apache2/.htpasswd user1    # Créer fichier + user1
sudo htpasswd /etc/apache2/.htpasswd user2        # Ajouter user2
echo "RT1: user1 user2" > /etc/apache2/groups
```
```apache
<Directory "/var/www/html/prive">
    AuthType Basic
    AuthName "Acces Reserve au groupe RT1"
    AuthUserFile /etc/apache2/.htpasswd
    AuthGroupFile /etc/apache2/groups
    Require group RT1
</Directory>
```

**Limitation de bande passante :**
```bash
sudo a2enmod ratelimit
```
```apache
SetOutputFilter RATE_LIMIT
SetEnv rate-limit 40    # 40 KB/s
```

**Pages personnelles (UserDir) :**
```bash
sudo a2enmod userdir
mkdir ~/public_html
chmod 755 /home/administrateur ~/public_html
```
Accès via : `http://IP/~administrateur/`

**Résolution DNS locale pour tests :**
```text
# /etc/hosts sur le client
192.31.25.12  vendeur.localhost client.localhost
```

### 21.2 Nginx + LEMP

**LEMP = Linux + nginx + MariaDB + PHP**

**Installation :**
```bash
sudo systemctl stop apache2
sudo apt install nginx mariadb-server php-fpm php-mysql -y
```

**Configuration PHP-FPM dans Nginx :**
```nginx
# /etc/nginx/sites-available/default
index index.php index.html index.htm;

location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
}
```

**phpMyAdmin avec Nginx :**
```bash
sudo apt install phpmyadmin    # Sélectionner "aucun serveur web"
sudo ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin
```

**Logs debug Nginx :**
```nginx
# /etc/nginx/nginx.conf
error_log /var/log/nginx/error.log debug;
```

### 21.3 Commandes de service

```bash
sudo systemctl start|stop|restart|reload|status apache2
sudo systemctl start|stop|restart|reload|status nginx
sudo systemctl enable apache2     # Démarrage automatique au boot
sudo apache2ctl configtest        # Vérifier la syntaxe de la config Apache
sudo nginx -t                     # Vérifier la syntaxe de la config Nginx
```

---

## 23. Téléphonie sur IP (VoIP / Asterisk)

### 22.1 Concepts VoIP

**SIP (Session Initiation Protocol)** : protocole de signalisation pour établir, modifier et terminer des sessions VoIP.  
**Port** : UDP 5060 (signalisation).  
**Encapsulation** : ETH | IP | UDP | SIP

**Flux d'un appel SIP :**
1. **INVITE** : le caller initie l'appel
2. **Ringing** : le callee sonne
3. **200 OK** : le callee décroche
4. **ACK** : confirmation de l'établissement
5. **RTP** : flux audio (Real-time Transport Protocol)
6. **BYE** : raccrochage

**Asterisk** : serveur IPBX open-source. Gère la signalisation SIP (via **PJSIP**) et le routage des appels via le **dialplan** (`extensions.conf`).

### 22.2 Configuration IVR (Interactive Voice Response)

```asterisk
; extensions.conf — Contexte principal
[AccueilAnnonce]
exten => s,1,Answer()
 same => n,Playback(/var/lib/asterisk/sounds/accueil)
 same => n,Background(/var/lib/asterisk/sounds/menu)
 same => n,WaitExten(5)

exten => 1,1,Dial(PJSIP/0106,12)
 same => n,VoiceMail(0106@default)    ; Si pas de réponse → messagerie

exten => 2,1,Dial(PJSIP/0206,12)
exten => 3,1,SayUnixTime()
```

**Enregistrement d'un message vocal :**
```asterisk
exten => 0901,1,Record(/var/lib/asterisk/sounds/accueil.gsm)
```

### 22.3 Trunk SIP entre deux serveurs Asterisk

**`pjsip.conf` — blocs clés :**
```ini
[siptrunk-auth]
type=auth
auth_type=userpass
username=Trunk06
password=12345

[siptrunk-identify]
type=identify
endpoint=siptrunk
match=10.15.251.146    ; IP du serveur distant (binôme)

[siptrunk-registration]
type=registration
server_uri=sip:10.15.251.146
client_uri=sip:Trunk06@10.15.251.146
```

**`extensions.conf` — routage vers le site distant :**
```asterisk
; Numéros commençant par 07XX → envoyer via le trunk
exten => _07XX,1,Dial(PJSIP/${EXTEN}@siptrunk,12)
```

**Vérification depuis la CLI Asterisk :**
```asterisk
pjsip show registrations    # Statut : Registered
pjsip show endpoints        # Statut : Reachable
```

---

## 24. Le Web : De l'URL à l'écran

### 23.1 Structure d'une URL

Une **URL (Uniform Resource Locator)** est l'adresse complète d'une ressource sur le Web.

```
https://www.example.com:443/dossier/page.html?id=42&lang=fr#section2
│──── │  │────────────│ │──│ │──────────────│ │─────────────│ │──────│
schéma   nom de domaine port   chemin            paramètres     fragment
```

| Partie | Exemple | Rôle |
|---|---|---|
| **Schéma** | `https://` | Protocole de communication |
| **Domaine** | `www.example.com` | Identifiant lisible du serveur |
| **Port** | `:443` | Port TCP (optionnel si standard : 80 pour HTTP, 443 pour HTTPS) |
| **Chemin** | `/dossier/page.html` | Ressource demandée sur le serveur |
| **Paramètres** | `?id=42&lang=fr` | Données transmises au serveur (méthode GET) |
| **Fragment** | `#section2` | Ancre dans la page (traité uniquement par le navigateur) |

---

### 23.2 Cycle complet d'une requête Web

**Étapes de l'ouverture de `https://www.example.com/page` :**

1. **Résolution DNS** : le navigateur interroge le serveur DNS pour obtenir l'IP de `www.example.com`
   - Cache local → `/etc/hosts` → Résolveur DNS du FAI → Serveurs racine → Serveur DNS authoritative

2. **Connexion TCP** : 3-way handshake vers l'IP obtenue, port 443

3. **Handshake TLS** : négociation du chiffrement, échange de certificats, établissement de la session HTTPS

4. **Requête HTTP** :
   ```http
   GET /page HTTP/1.1
   Host: www.example.com
   Accept: text/html,application/xhtml+xml
   User-Agent: Mozilla/5.0 ...
   Accept-Language: fr-FR,fr;q=0.9
   ```

5. **Réponse HTTP** :
   ```http
   HTTP/1.1 200 OK
   Content-Type: text/html; charset=UTF-8
   Content-Length: 4256
   Cache-Control: max-age=3600

   <!DOCTYPE html>
   <html>...
   ```

6. **Rendu** : le navigateur parse le HTML, charge les ressources (CSS, JS, images), exécute le JavaScript, affiche la page

---

### 23.3 TLS/SSL — Chiffrement du Web

**TLS (Transport Layer Security)** encapsule HTTP pour créer HTTPS. Il assure :
- **Confidentialité** : les données sont chiffrées (illisibles en cas d'interception)
- **Intégrité** : toute modification des données est détectée
- **Authentification** : le certificat prouve l'identité du serveur

**Handshake TLS 1.3 (simplifié) :**
```
Client                              Serveur
  | ── ClientHello ──────────────> |  (versions supportées, algos)
  | <── ServerHello ─────────────  |  (version choisie, certificat)
  | ── Finished ─────────────────> |  (clé de session établie)
  |   [Communication chiffrée]     |
```

**Certificat SSL/TLS** : fichier signé par une **Autorité de Certification (CA)** qui atteste que la clé publique appartient bien au domaine indiqué. Visualisable en cliquant sur le cadenas dans le navigateur.

---

### 23.4 HTTP/1.1, HTTP/2 et HTTP/3

| Version | Caractéristiques | Transport |
|---|---|---|
| **HTTP/1.1** | Une requête par connexion TCP (keep-alive améliore légèrement). Problème de head-of-line blocking. | TCP |
| **HTTP/2** | Multiplexage : plusieurs requêtes simultanées sur une seule connexion TCP. Header compression (HPACK). | TCP + TLS |
| **HTTP/3** | Remplace TCP par **QUIC** (UDP + fiabilité intégrée). Élimination du head-of-line blocking. Connexion plus rapide. | QUIC (UDP) |

---

### 23.5 En-têtes HTTP importants

| En-tête | Type | Description |
|---|---|---|
| `Host` | Requête | Domaine ciblé (essentiel pour les Virtual Hosts) |
| `User-Agent` | Requête | Identifiant du client (navigateur, bot) |
| `Accept` | Requête | Types de contenu acceptés (`text/html`, `application/json`) |
| `Authorization` | Requête | Jeton d'authentification (Bearer, Basic) |
| `Cookie` | Requête | Cookies envoyés au serveur |
| `Content-Type` | Requête/Réponse | Type du corps (`application/json`, `multipart/form-data`) |
| `Cache-Control` | Réponse | Directives de mise en cache (`max-age=3600`, `no-cache`) |
| `Set-Cookie` | Réponse | Définir un cookie dans le navigateur |
| `Location` | Réponse | URL de redirection (avec code 301/302) |
| `Strict-Transport-Security` | Réponse | Force HTTPS (HSTS) |

---

## 25. Anatomie d'un Navigateur Web

### 24.1 Les composants internes

Un navigateur moderne n'est pas un programme simple — c'est un système divisé en plusieurs sous-systèmes spécialisés qui communiquent entre eux :

| Composant | Rôle |
|---|---|
| **Interface Utilisateur (UI)** | Barre d'adresse, boutons précédent/suivant, onglets, favoris. Tout ce que voit l'utilisateur hors page. |
| **Moteur du navigateur (Browser Engine)** | Chef d'orchestre. Coordonne les échanges entre l'UI et le moteur de rendu. |
| **Moteur de rendu (Rendering Engine)** | Parse HTML + CSS, construit les arbres DOM/CSSOM, calcule la mise en page et dessine les pixels. |
| **Couche réseau (Networking)** | Gère les requêtes HTTP/HTTPS, DNS, TCP, le cache réseau, les cookies. |
| **Interpréteur JavaScript (JS Engine)** | Compile et exécute le code JS, interagit avec le DOM. |
| **Stockage** | Cookies, LocalStorage, SessionStorage, IndexedDB, cache service worker. |

**Moteurs de rendu et JS engines par navigateur :**

| Navigateur | Moteur de rendu | JS Engine |
|---|---|---|
| Chrome, Edge, Opera | **Blink** | **V8** |
| Firefox | **Gecko** | **SpiderMonkey** |
| Safari | **WebKit** | **JavaScriptCore** |

> **Note :** Node.js utilise également V8 — le même moteur que Chrome — ce qui explique que JavaScript puisse s'exécuter côté serveur.

---

### 24.2 La barre d'adresse : recherche vs navigation directe

La barre d'adresse d'un navigateur fait deux métiers distincts selon ce que l'utilisateur tape :

| Ce que l'utilisateur tape | Comportement du navigateur |
|---|---|
| `youtube.com` | Détecte un nom de domaine (présence d'un TLD, pas d'espaces). Résolution DNS → connexion directe. |
| `youtube` | Mot-clé sans TLD. Envoie vers le moteur de recherche configuré. |
| `ma recherche ici` | Espaces détectés → encodage URL → requête vers moteur de recherche. |

**Logique de détection (simplifiée) :**
```
saisie contient un point ET pas d'espace
    → probablement une URL → connexion directe
sinon
    → mots-clés → https://www.google.com/search?q=ma+recherche+ici
```

**Encodage des paramètres de recherche :**
- Les espaces deviennent `+` ou `%20`
- Les caractères spéciaux sont encodés en `%XX` (URL encoding, RFC 3986)
- Exemple : `BUT R&T Artois` → `BUT+R%26T+Artois`

---

### 24.3 Le pipeline de rendu (De la requête au pixel)

Une fois le HTML/CSS reçu du serveur, le navigateur enchaîne ces étapes :

```text
[Flux HTML] ──> Parsing ──> [ DOM Tree  ] ──┐
                                             ├──> [ Render Tree ] ──> Layout ──> Painting
[Flux CSS ] ──> Parsing ──> [ CSSOM Tree] ──┘
```

**Détail des étapes :**

1. **Parsing HTML → DOM Tree**
   Le moteur de rendu lit le HTML octet par octet, le tokenise (balises, texte, attributs), et construit un arbre de nœuds : le **DOM (Document Object Model)**. Chaque balise devient un nœud.

2. **Parsing CSS → CSSOM**
   Les feuilles de style sont analysées en parallèle pour construire le **CSSOM (CSS Object Model)** : un arbre de règles de style associées à des sélecteurs.

3. **Render Tree**
   Le navigateur fusionne DOM + CSSOM. Les éléments invisibles (`display: none`, `<head>`, `<script>`) sont exclus. Chaque nœud visible porte maintenant ses styles calculés.

4. **Layout / Reflow**
   Le moteur calcule la **position et la taille** exactes de chaque boîte en fonction de la taille du viewport. C'est l'étape la plus coûteuse en CPU pour les pages complexes.

5. **Painting**
   L'arbre de rendu est rastérisé en pixels. Le GPU est souvent utilisé pour cette phase (accélération matérielle).

---

### 24.4 JavaScript et le rendu bloquant

Par défaut, un `<script>` dans le HTML **bloque** le parsing HTML le temps que le script soit téléchargé et exécuté — car JS peut modifier le DOM en cours de construction.

**Solutions :**

| Attribut | Comportement |
|---|---|
| `<script>` (aucun) | Bloque le parsing HTML. Mauvaise pratique pour les scripts externes. |
| `<script defer>` | Téléchargé en parallèle, exécuté **après** la fin du parsing HTML. |
| `<script async>` | Téléchargé en parallèle, exécuté **dès** que disponible (ordre non garanti). |

**Reflow et Repaint :**
- Modifier le DOM via JS (ajouter un élément, changer une taille) → déclenche un **reflow** (recalcul du layout) puis un **repaint**
- Les animations CSS sont préférables aux animations JS pour éviter les reflows fréquents

---

### 24.5 Cache navigateur

| Type de cache | Durée | Contenu |
|---|---|---|
| **Mémoire (RAM)** | Session en cours uniquement | Pages, images déjà consultées |
| **Disque** | Persistant (jours/semaines) | Fichiers statiques (JS, CSS, images) |

**En-têtes HTTP qui contrôlent le cache :**

```http
Cache-Control: max-age=86400        # Utiliser le cache pendant 24h
Cache-Control: no-cache             # Toujours revalider avec le serveur
Cache-Control: no-store             # Ne jamais mettre en cache
ETag: "abc123"                      # Empreinte du fichier (version)
Last-Modified: Mon, 12 May 2025 ...
```

**Comportements de rechargement :**
- `F5` / Reload normal : utilise le cache si valide
- `Ctrl+Shift+R` / Hard reload : ignore le cache, refetch tout
- Vider le cache manuellement : supprime tous les fichiers mis en cache sur le disque

---

## 26. La Programmation : PHP et Python

### 25.1 PHP — Langage côté serveur

**PHP (PHP: Hypertext Preprocessor)** est un langage de script interprété exécuté côté serveur. Le code PHP génère du HTML qui est renvoyé au client.

**Intégration dans Apache/Nginx :**
- Apache : module `mod_php` ou PHP-FPM
- Nginx : toujours via **PHP-FPM** (FastCGI Process Manager) — voir chapitre 20

**Syntaxe de base :**
```php
<?php
// Variables (typage dynamique)
$nom = "Briac";
$age = 20;
$prix = 19.99;
$actif = true;

// Tableaux
$vlan = ["ADMIN", "PERSONNEL", "PROD"];
$config = ["ip" => "192.168.1.1", "masque" => "255.255.255.0"];

// Structures de contrôle
if ($age >= 18) {
    echo "Majeur";
} else {
    echo "Mineur";
}

foreach ($vlan as $index => $nom) {
    echo "VLAN $index : $nom\n";
}

// Fonctions
function calculerBroadcast($reseau, $cidr) {
    $bits = 32 - $cidr;
    $hosts = pow(2, $bits) - 1;
    return long2ip(ip2long($reseau) + $hosts);
}

echo calculerBroadcast("192.168.1.0", 24);  // 192.168.1.255
?>
```

**Connexion à une base de données (PDO) :**
```php
<?php
try {
    $pdo = new PDO("mysql:host=localhost;dbname=reseau", "user", "motdepasse");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Requête préparée (protection contre l'injection SQL)
    $stmt = $pdo->prepare("SELECT * FROM equipements WHERE vlan = ?");
    $stmt->execute([10]);
    $resultats = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($resultats as $equip) {
        echo $equip['nom'] . " — " . $equip['ip'] . "\n";
    }
} catch (PDOException $e) {
    echo "Erreur : " . $e->getMessage();
}
?>
```

**Variables superglobales PHP :**

| Variable | Contenu |
|---|---|
| `$_GET` | Paramètres passés dans l'URL (`?id=42`) |
| `$_POST` | Données d'un formulaire HTML (méthode POST) |
| `$_SESSION` | Variables de session (persistantes entre pages) |
| `$_COOKIE` | Cookies du navigateur |
| `$_SERVER` | Infos du serveur et de la requête (`$_SERVER['REMOTE_ADDR']`) |

---

### 25.2 Python — Le couteau suisse

Python est un langage interprété polyvalent : scripts réseau, développement web, data science, automatisation, IA.

**Syntaxe de base :**
```python
# Variables et types
nom = "Briac"
age = 20
pi = 3.14
actif = True

# Listes et dictionnaires
vlans = ["ADMIN", "PERSONNEL", "PROD"]
config = {"ip": "192.168.1.1", "masque": "255.255.255.0", "cidr": 24}

# Boucles et conditions
for vlan in vlans:
    print(f"VLAN : {vlan}")

if config["cidr"] >= 24:
    print("Petit réseau")

# Fonctions
def calculer_hotes(cidr):
    return 2 ** (32 - cidr) - 2

print(calculer_hotes(24))   # 254
print(calculer_hotes(30))   # 2
```

**Scripts réseau courants :**
```python
import socket
import ipaddress

# Résolution DNS
ip = socket.gethostbyname("iut-rt.univ-artois.fr")
print(f"IP : {ip}")

# Calculs réseau avec ipaddress
reseau = ipaddress.IPv4Network("192.168.10.0/26", strict=False)
print(f"Réseau     : {reseau.network_address}")
print(f"Broadcast  : {reseau.broadcast_address}")
print(f"Hôtes      : {reseau.num_addresses - 2}")
print(f"Masque     : {reseau.netmask}")

# Scan de ports simple (éducatif)
for port in [22, 80, 443, 3306]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex(("192.168.1.1", port))
    print(f"Port {port}: {'OUVERT' if result == 0 else 'FERMÉ'}")
    sock.close()
```

**Frameworks web Python :**

| Framework | Type | Usage |
|---|---|---|
| **Flask** | Micro-framework | APIs REST légères, prototypes, petits sites |
| **Django** | Framework complet | Applications web complexes, ORM intégré, admin auto |
| **FastAPI** | Moderne, asynchrone | APIs REST hautes performances, documentation auto |

```python
# Exemple Flask — API REST simple
from flask import Flask, jsonify

app = Flask(__name__)

equipements = [
    {"id": 1, "nom": "R1", "ip": "192.168.1.254", "type": "routeur"},
    {"id": 2, "nom": "SW1", "ip": "192.168.1.10", "type": "switch"},
]

@app.route("/api/equipements")
def get_equipements():
    return jsonify(equipements)

@app.route("/api/equipements/<int:id>")
def get_equipement(id):
    equip = next((e for e in equipements if e["id"] == id), None)
    return jsonify(equip) if equip else ("Not found", 404)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
```

---

### 25.3 JavaScript et frameworks frontend

**JavaScript (JS)** s'exécute dans le navigateur (côté client). Il permet l'interactivité des pages sans rechargement.

**React — Bibliothèque UI de Meta :**

React découpe l'interface en **composants** réutilisables. Quand les données changent, seuls les composants affectés sont re-rendus (Virtual DOM), sans recharger la page entière.

```jsx
// Composant React simple
function CarteEquipement({ nom, ip, vlan }) {
    return (
        <div className="carte">
            <h3>{nom}</h3>
            <p>IP : {ip}</p>
            <p>VLAN : {vlan}</p>
        </div>
    );
}

// Utilisation
<CarteEquipement nom="R1" ip="192.168.1.254" vlan={10} />
```

**Frameworks CSS :**

| Framework | Approche | Usage |
|---|---|---|
| **Tailwind CSS** | Utility-first — classes atomiques directement dans le HTML (`flex`, `p-4`, `text-blue-500`) | Design custom rapide, pas de CSS à écrire |
| **Bootstrap** | Composants pré-fabriqués (navbar, grille, boutons) | Prototypage rapide, maquettes |

**Tailwind vs Bootstrap :**
- **Tailwind** : plus de liberté, classes dans le HTML, bundle final plus petit (tree-shaking), courbe d'apprentissage plus raide
- **Bootstrap** : plus de composants prêts à l'emploi, plus rapide à prendre en main, apparence plus générique

---

## 27. Administration Cisco IOS — Aide-mémoire

### 26.1 Modes IOS

```
>  : Mode utilisateur (User EXEC)
#  : Mode privilégié (Privileged EXEC) — accès via : enable
(config)#  : Mode configuration globale — accès via : configure terminal
(config-if)#  : Mode configuration d'interface
(config-router)#  : Mode configuration routage
(config-vlan)#  : Mode configuration VLAN
```

**Navigation :**
```cisco
enable                    ! Entrer en mode privilégié
configure terminal        ! Entrer en mode configuration
end / Ctrl+Z              ! Retour en mode privilégié
exit                      ! Remonter d'un niveau
do show ip route          ! Exécuter une commande EXEC depuis le mode config
```

### 26.2 Configuration de base

```cisco
hostname SW1                        ! Nommer l'équipement
no ip domain-lookup                 ! Désactiver résolution DNS (évite les attentes)
service password-encryption         ! Chiffrer les mots de passe

enable secret monmotdepasse         ! Mot de passe privilégié (chiffré)
line console 0
 password cisco
 login

write memory                        ! Sauvegarder la configuration
! ou
copy running-config startup-config
```

### 26.3 Configuration IP d'une interface

**Routeur :**
```cisco
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown                         ! Activer l'interface (DOWN par défaut)
 description Vers_LAN_Admin
 exit
```

**Interface série (WAN physique) :**
```cisco
interface Serial0/1/0
 ip address 10.1.0.1 255.255.0.0
 clock rate 128000                   ! UNIQUEMENT côté DCE
 no shutdown
 exit
```

**Switch — IP de gestion :**
```cisco
interface vlan 1                     ! Interface de gestion
 ip address 192.168.1.10 255.255.255.0
 no shutdown
 exit
ip default-gateway 192.168.1.1
```

### 26.4 Commandes de vérification essentielles

```cisco
! ─── Interfaces ───
show ip interface brief              ! Tableau synthétique : IP, état
show interfaces GigabitEthernet0/0   ! Détails complets d'une interface
show controllers Serial0/0/0         ! DCE ou DTE sur une liaison série

! ─── Routage ───
show ip route                        ! Table de routage
show ip protocols                    ! Protocoles de routage actifs
show ip ospf neighbor                ! Voisins OSPF
show ip rip database                 ! Base de données RIP

! ─── VLAN & Switch ───
show vlan brief                      ! Liste des VLANs et ports
show interfaces trunk                ! Ports trunk et VLANs autorisés
show mac address-table               ! Table MAC
show spanning-tree                   ! État STP
show etherchannel summary            ! Résumé des EtherChannels

! ─── Général ───
show running-config                  ! Configuration active en RAM
show startup-config                  ! Configuration sauvegardée en NVRAM
show version                         ! Version IOS, modèle, uptime
ping 192.168.1.10                    ! Test de connectivité
traceroute 192.168.2.10              ! Tracer le chemin
```

### 26.5 Cisco Packet Tracer — spécificités

- **Lien vert** = interface UP (couches 1 et 2 actives)
- **Lien orange** = initialisation STP
- **Lien rouge** = interface DOWN
- **Mode Simulation** : visualiser le contenu de chaque paquet étape par étape
- Configuration PC : Desktop > IP Configuration
- `no ip domain-lookup` : évite que Cisco essaie de résoudre les commandes mal tapées comme des noms DNS (économise du temps)

---

## 28. Commandes Réseau Linux — Aide-mémoire

### 27.1 Gestion des interfaces (iproute2)

```bash
# ─── Afficher ───
ip a                          # Toutes les interfaces et leurs adresses
ip -4 -br a                   # IPv4 seulement, format compact
ip link show                  # État des interfaces (UP/DOWN)
ip r                          # Table de routage
ip n                          # Table ARP (voisins)

# ─── Configurer ───
sudo ip a add 192.168.0.1/24 dev enp0s8      # Ajouter une IP
sudo ip a del 192.168.0.1/24 dev enp0s8      # Supprimer une IP
sudo ip link set dev enp0s8 up               # Activer une interface
sudo ip link set dev enp0s8 down             # Désactiver une interface
sudo ip route add default via 192.168.0.1    # Route par défaut
sudo ip route add 10.0.0.0/8 via 192.168.1.254  # Route statique spécifique
sudo dhclient enp0s3                         # Obtenir une IP via DHCP
```

### 27.2 Test de connectivité

```bash
ping 8.8.8.8                    # Test ICMP
ping -c 4 192.168.1.1           # 4 pings seulement
traceroute 8.8.8.8              # Tracer le chemin (utilise UDP par défaut sous Linux)
tracepath 8.8.8.8               # Variante sans root requis

# DNS
nslookup iut-rt                 # Résolution DNS simple
dig iut-rt                      # Résolution DNS détaillée
host iut-rt                     # Résolution rapide

# ARP
arp -a                           # Table ARP
ip n flush dev enp0s3            # Vider le cache ARP d'une interface
```

### 27.3 Analyse de ports et connexions

```bash
ss -tnp                          # Connexions TCP actives avec PID
ss -unp                          # Connexions UDP actives
ss -n | grep 8000                # Filtrer par port
netstat -tulnp                   # Ancien équivalent (net-tools)

# Netcat — simuler client/serveur
nc -l 8000                       # Écouter sur le port 8000 (serveur)
nc localhost 8000                 # Se connecter au port 8000 (client)
nc -u -l 9000                    # Mode UDP serveur
nc -u localhost 9000              # Mode UDP client
```

### 27.4 Wireshark / Capture de trafic

```bash
sudo wireshark &                  # Lancer Wireshark en arrière-plan
sudo tcpdump -i enp0s3            # Capture en ligne de commande
sudo tcpdump -i enp0s3 port 80    # Filtrer par port
```

**Filtres Wireshark courants :**

| Filtre | Signification |
|---|---|
| `tcp` | Tout le trafic TCP |
| `udp` | Tout le trafic UDP |
| `icmp` | Pings et messages ICMP |
| `tcp.port == 80` | Trafic HTTP |
| `arp` | Requêtes et réponses ARP |
| `ip.addr == 192.168.1.1` | Trafic de/vers cette IP |
| `tcp.flags.syn == 1` | Paquets SYN (début de connexion) |

### 27.5 Scans Nmap

```bash
sudo nmap -sS localhost           # Scan SYN Stealth (discret)
sudo nmap -sV 192.168.1.0/24     # Scan réseau + détection de versions
nmap -p 80,443,22 192.168.1.1    # Scanner des ports spécifiques
```

**Types de scans :**

| Option | Type | Comportement |
|---|---|---|
| `-sS` | SYN Stealth | Envoie SYN, attend SYN/ACK, répond RST (discret) |
| `-sT` | TCP Connect | Connexion complète (loggée) |
| `-sU` | UDP | Scanne les ports UDP |
| `-sX` | Xmas | Flags FIN + PSH + URG allumés |
| `-sN` | Null | Aucun flag |

⚠️ Scanner des machines tiers sans autorisation est illégal.

### 27.6 Gestion des services systemd

```bash
sudo systemctl start apache2
sudo systemctl stop apache2
sudo systemctl restart apache2    # Stop + start
sudo systemctl reload apache2     # Recharger la config sans interruption
sudo systemctl enable apache2     # Démarrage automatique au boot
sudo systemctl disable apache2
sudo systemctl status apache2     # État du service
```

### 27.7 Configuration DNS client

```bash
# Fichier /etc/resolv.conf
echo 'nameserver 172.18.26.101' > /etc/resolv.conf
echo 'nameserver 1.1.1.1' >> /etc/resolv.conf

# Résolution DNS locale sans serveur (/etc/hosts)
echo '192.168.1.10  serveur.local' >> /etc/hosts

# Proxy pour accès Internet (IUT)
# Dans Firefox : Préférences > Réseau > Manuel
# Proxy HTTP : cache-etu.univ-artois.fr  Port : 3128
```

### 27.8 IP Forwarding et iptables

```bash
# IP Forwarding
cat /proc/sys/net/ipv4/ip_forward            # Vérifier (0 ou 1)
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward  # Activer (temporaire)
sudo sysctl -w net.ipv4.ip_forward=1         # Activer via sysctl

# iptables NAT
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
sudo iptables -t nat -L -v -n                # Lister les règles NAT

# Sauvegarder/restaurer les règles iptables
sudo iptables-save > /etc/iptables/rules.v4
sudo iptables-restore < /etc/iptables/rules.v4
```

## 29. Administration Windows Server & Active Directory

### 29.1 Vue d'ensemble de l'architecture

Windows Server est un système d'exploitation serveur de Microsoft, utilisé pour centraliser l'administration des ressources d'un réseau d'entreprise. Les rôles principaux installables sont :

| Rôle | Fonction |
|---|---|
| AD DS (Active Directory Domain Services) | Annuaire centralisé : utilisateurs, groupes, ordinateurs |
| DHCP Server | Attribution automatique d'adresses IP |
| DNS Server | Résolution de noms dans le domaine |
| File Services | Partage de fichiers et gestion NTFS |
| Print Services | Déploiement d'imprimantes réseau |

### 29.2 Active Directory Domain Services (AD DS)

**Concepts fondamentaux :**

- **Domaine** : unité administrative de base. Exemple : `dom-LeMeillat.local`. Tous les objets (utilisateurs, machines) appartiennent à un domaine.
- **Contrôleur de domaine (DC)** : serveur qui héberge la base de données AD et authentifie les utilisateurs.
- **Unité d'Organisation (OU)** : dossier logique permettant de regrouper des objets et d'y appliquer des GPO.
- **Groupe Sécurité / Étendue Globale** : type pour gestion de droits NTFS et partages, visible dans tout le domaine.

**Dépendance critique : le DNS**

L'AD repose entièrement sur le DNS. Le client doit pointer son DNS vers l'IP du contrôleur de domaine pour résoudre `dom-exemple.local`. Si le DNS est mal configuré, la jonction au domaine échoue.

```dos
:: Vérifier la résolution DNS du domaine
nslookup dom-LeMeillat.local
```

---

### 29.3 Stratégies de Groupe (GPO)

Les **GPO** (Group Policy Objects) sont des ensembles de règles poussées automatiquement par le DC lors de chaque ouverture de session ou démarrage.

**Hiérarchie d'application (du moins au plus prioritaire) :**

```
Local → Site → Domaine → OU
```

**GPO courantes :**

| Paramètre | Chemin dans GPMC |
|---|---|
| Complexité mot de passe | Config. Ordinateur > Stratégies > Paramètres Windows > Sécurité > Stratégie de compte |
| Droit de session locale (`SeInteractiveLogonRight`) | Config. Ordinateur > Stratégies > Paramètres Windows > Droits utilisateur |
| Déploiement de logiciels (MSI) | Config. Ordinateur > Stratégies > Paramètres logiciel > Installation de logiciel |
| Scripts de connexion | Config. Utilisateur > Stratégies > Paramètres Windows > Scripts |

```dos
:: Forcer l'application immédiate des GPO sur le client
gpupdate /force
```

---

### 29.4 Partages réseau et sécurité NTFS

**Deux niveaux de permissions coexistent :**

| Niveau | Portée | Outil |
|---|---|---|
| Permissions de **partage** (SMB) | Accès réseau uniquement | Onglet "Partage" / `New-SmbShare` |
| Permissions **NTFS** | Local ET réseau | Onglet "Sécurité" / `icacls` |

> La permission effective est **l'intersection** (la plus restrictive) entre les deux niveaux.

**Partage masqué** : le suffixe `$` (`etu01$`) rend le dossier invisible dans le parcours réseau standard. Accès direct toujours possible via UNC :

```
\\srv-LeMeillat\etu01$
```

**Commandes icacls :**

```dos
:: Contrôle total avec héritage (fichiers + sous-dossiers)
icacls C:\volume\Utilisateurs\etu01 /grant "DOM\etu01:(OI)(CI)F"

:: Lecture seule
icacls C:\volume\Utilisateurs\etu01 /grant "DOM\Profs:(OI)(CI)R"
```

| Drapeau | Signification |
|---|---|
| `(OI)` | Object Inherit — héritage sur les fichiers |
| `(CI)` | Container Inherit — héritage sur les sous-dossiers |
| `F` | Full Control |
| `R` | Read |
| `M` | Modify |

---

### 29.5 Profils Itinérants et NETLOGON

**Profil itinérant** : le profil de l'utilisateur est stocké sur le serveur. Quelle que soit la machine d'ouverture de session, il retrouve son environnement complet.

Chemin configuré dans les propriétés du compte AD :

```
\\srv-LeMeillat\Utilisateurs\%username%\profil
```

**NETLOGON** : partage spécial du DC contenant les scripts de connexion. Chemin physique :

```
C:\Windows\SYSVOL\sysvol\<domaine>\scripts\
```

Script générique `common.bat` monté à chaque ouverture de session :

```dos
@echo off
net use R: /delete /yes
net use R: \\srv-LeMeillat\Utilisateurs\%USERNAME%
```

La variable `%USERNAME%` est résolue dynamiquement — un seul script pour tous les utilisateurs.

---

### 29.6 Automatisation PowerShell

PowerShell est le shell natif de Windows Server pour l'automatisation de masse.

**Commandes AD essentielles :**

```powershell
# Créer un utilisateur
New-ADUser -Name "Prenom Nom" -SamAccountName "nom" `
           -UserPrincipalName "nom@domaine.local" `
           -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) `
           -Enabled $true -Path "CN=Users,DC=domaine,DC=local" `
           -ScriptPath "common.bat"

# Ajouter à un groupe
Add-ADGroupMember -Identity "Groupe" -Members "nom"

# Supprimer un utilisateur
Remove-ADUser -Identity "nom" -Confirm:$false

# Lister les membres d'un groupe
Get-ADGroupMember -Identity "Groupe"
```

**Commandes SMB + NTFS (script complet) :**

```powershell
# Créer le répertoire physique
New-Item -Path "C:\volume\Utilisateurs\nom" -ItemType Directory -Force

# Créer le partage masqué
New-SmbShare -Name "nom`$" -Path "C:\volume\Utilisateurs\nom" -FullAccess "Tout le monde"

# Appliquer les droits NTFS
icacls "C:\volume\Utilisateurs\nom" /grant "DOMAINE\nom:(OI)(CI)F"
icacls "C:\volume\Utilisateurs\nom" /grant "Administrateurs:(OI)(CI)F"

# Rollback complet
Remove-ADUser -Identity "nom" -Confirm:$false
Remove-SmbShare -Name "nom`$" -Force
Remove-Item -Path "C:\volume\Utilisateurs\nom" -Recurse -Force
```

---

### 29.7 Quotas de disque

| Paramètre | Valeur |
|---|---|
| Limite disque | 1 Go |
| Niveau d'avertissement | 900 Mo |
| Comportement au dépassement | Écriture refusée |

Activation : `Gestion des disques → Propriétés du volume → Onglet Quota`

---

### 29.8 Récapitulatif des commandes Windows Server

| Commande | Rôle |
|---|---|
| `gpupdate /force` | Forcer l'application des GPO |
| `gpresult /r` | Afficher les GPO appliquées à la session courante |
| `ipconfig /all` | Afficher la configuration IP complète |
| `net use` | Monter / démonter des lecteurs réseau |
| `icacls <chemin>` | Afficher ou modifier les droits NTFS |
| `nslookup <domaine>` | Tester la résolution DNS |
| `Get-ADUser -Filter *` | Lister tous les utilisateurs AD |
| `Get-SmbShare` | Lister les partages réseau actifs |
| `Test-ComputerSecureChannel` | Vérifier la relation de confiance machine/domaine |

---

## Annexe A — Tableau des protocoles de référence

| Protocole | Couche | Port | Transport | Fonction |
|---|:-:|:-:|:-:|---|
| Ethernet | 2 | — | — | Trames sur LAN, adresses MAC |
| ARP | 2↔3 | — | — | IP → MAC sur LAN |
| IP | 3 | — | — | Routage global (adresses IPv4/IPv6) |
| ICMP | 3 | — | — | Diagnostic (ping, erreurs, traceroute) |
| RIP | 3 | 520 | UDP | Routage dynamique distance-vector |
| OSPF | 3 | — | IP (89) | Routage dynamique link-state |
| TCP | 4 | — | — | Transport fiable, orienté connexion |
| UDP | 4 | — | — | Transport rapide, sans connexion |
| DNS | 7 | 53 | UDP/TCP | Nom de domaine → IP |
| DHCP | 7 | 67/68 | UDP | Attribution automatique IP |
| HTTP | 7 | 80 | TCP | Web non chiffré |
| HTTPS | 7 | 443 | TCP | Web chiffré (HTTP + TLS) |
| SSH | 7 | 22 | TCP | Shell distant sécurisé |
| FTP | 7 | 20/21 | TCP | Transfert de fichiers |
| Telnet | 7 | 23 | TCP | Shell distant non chiffré (déprécié) |
| SIP | 7 | 5060 | UDP | Signalisation VoIP |

---

## Annexe B — Calculs rapides : mémo IPv4

**Étant donné une adresse `A.B.C.D/n` :**

| À calculer | Méthode |
|---|---|
| Adresse réseau | `A.B.C.D AND masque` (bits HostID à 0) |
| Broadcast | Bits HostID à 1 |
| Première IP utilisable | Adresse réseau + 1 |
| Dernière IP utilisable | Broadcast − 1 |
| Nombre d'hôtes | 2^(32−n) − 2 |
| Masque décimal | Compter les 1 par octet |

**Exemples de calculs fréquents en examen :**

| Réseau | Masque | Broadcast | Hôtes | 1ère IP | Dernière IP |
|---|---|---|:-:|---|---|
| `192.168.1.128/25` | `255.255.255.128` | `192.168.1.255` | 126 | `192.168.1.129` | `192.168.1.254` |
| `192.168.10.0/26` | `255.255.255.192` | `192.168.10.63` | 62 | `192.168.10.1` | `192.168.10.62` |
| `192.168.10.64/26` | `255.255.255.192` | `192.168.10.127` | 62 | `192.168.10.65` | `192.168.10.126` |
| `10.1.4.32/27` | `255.255.255.224` | `10.1.4.63` | 30 | `10.1.4.33` | `10.1.4.62` |
| `172.16.0.0/16` | `255.255.0.0` | `172.16.255.255` | 65 534 | `172.16.0.1` | `172.16.255.254` |
| `10.0.0.0/8` | `255.0.0.0` | `10.255.255.255` | 16 777 214 | `10.0.0.1` | `10.255.255.254` |

---

## Annexe C — Mnémotechniques et points de vigilance

**Points critiques lors d'une soutenance :**

1. **"Pourquoi une adresse MAC change à chaque saut ?"**  
   → La MAC est locale : elle identifie le prochain équipement sur le lien physique actuel. Quand un routeur retransmet, il réécrit la MAC source (sa propre MAC) et la MAC destination (MAC du prochain saut). L'IP source/destination ne change jamais (sauf NAT).

2. **"Pourquoi pas de routage sans masque ?"**  
   → Le masque dit au routeur quelle partie de l'IP est "réseau" et quelle partie est "hôte". Sans masque, impossible de faire l'opération AND pour trouver l'adresse réseau et décider si la destination est locale ou distante.

3. **"Quelle est la différence entre ARP et DNS ?"**  
   → ARP résout IP→MAC (couche 2, portée locale, réponse directe). DNS résout Nom→IP (couche 7, portée globale, serveur centralisé).

4. **"Pourquoi TCP est fiable et pas UDP ?"**  
   → TCP numérote chaque octet, le récepteur envoie des ACK, et l'émetteur retransmet si nécessaire. UDP envoie et oublie.

5. **"Différence ACL Standard vs Étendue ?"**  
   → Standard = filtre IP source uniquement, placée près de la destination. Étendue = filtre source + destination + protocole + port, placée près de la source.

6. **"Pourquoi `no auto-summary` dans RIP ?"**  
   → Sans ça, RIPv2 regroupe les routes par classe. Si on a `10.1.0.0/16` et `192.168.1.0/24`, RIP annoncerait `10.0.0.0/8` et `192.168.0.0/24` (classful). Avec des masques différents mélangés, ça causerait des erreurs de routage.

7. **"Pourquoi OSPF est meilleur que RIP ?"**  
   → OSPF est link-state (carte complète vs vecteur de distance), convergence rapide, pas de limite de sauts, métrique basée sur la bande passante (pas juste le nombre de sauts).

8. **"Pourquoi NAT ?"**  
   → Les adresses privées (RFC 1918) ne sont pas routables sur Internet. NAT masque toutes les machines d'un réseau privé derrière une seule IP publique, ce qui économise des adresses IPv4 et isole le réseau interne.

9. **"Différence entre `deny any` et `permit any` dans une ACL ?"**  
   → Toute ACL se termine par un `deny any` implicite (tout ce qui n'est pas explicitement autorisé est refusé). Si on veut autoriser le reste après avoir bloqué certaines choses, il FAUT ajouter `permit any` explicitement.

10. **"Qu'est-ce que le TTL ?"**  
    → Champ de l'en-tête IP décrémenté de 1 à chaque routeur. Quand il atteint 0, le routeur détruit le paquet et envoie un ICMP "Time Exceeded" à la source. Empêche les boucles infinies. Valeurs initiales : 64 (Linux), 128 (Windows), 255 (Cisco).

---

*Document rédigé à partir des TPs, cours et SAE de 1ère année BUT R&T — IUT d'Artois, Béthune.*  
*Briac Le Meillat — 2025/2026*
