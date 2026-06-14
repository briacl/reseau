# Plan — Bible du Réseau : Visualiseur Web Interactif

Un seul fichier HTML (`bible_code/visualiseur_web.html`) organisé en **modules navigables**,
qui reproduit ce que chaque script terminal affiche, mais de manière interactive et animée.

---

## Architecture générale de la page

```
┌────────────────────────────────────────────────────────────────┐
│  BARRE DE NAVIGATION LATÉRALE (fixe, gauche)                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  M1 · Sniffer Ethernet                                   │  │
│  │  M1 · ARP Forge                                          │  │
│  │  M1 · Encapsulateur                    ← actif           │  │
│  │  M2 · UDP Echo                                           │  │
│  │  M2 · TCP Handshake                                      │  │
│  │  M3 · Mini DNS                                           │  │
│  │  M3 · Mini DHCP                                          │  │
│  │  M4 · Serveur HTTP                                       │  │
│  │  M4 · Proxy HTTP                                         │  │
│  │  M4 · Proxy HTTPS                                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ZONE PRINCIPALE (droite, scrollable)                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Contenu du module sélectionné (voir détails ci-dessous) │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

Chaque module a la même **structure interne** :
1. Bandeau couche OSI coloré (Couche 2 = bleu, 3 = vert, 4 = orange, App = violet)
2. Analogie en italique
3. Schéma interactif
4. Zone "crash test" avec la commande de lancement

---

## Module 1.1 — Sniffer Ethernet

**Ce que le terminal montre :** une ligne par trame : `interface | MAC src → MAC dst | EtherType | taille`

**Visuel web :**

```
┌─────────────────────────────────────────────────────────────────┐
│  COUCHE 2 — Liaison                                             │
│                                                                 │
│  "La carte réseau est une oreille collée au mur : elle entend  │
│   TOUTES les trames, même celles qui ne lui sont pas destinées" │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  SIMULATEUR DE TRAFIC EN DIRECT                         │   │
│  │                                                         │   │
│  │  [● Démarrer la simulation]                             │   │
│  │                                                         │   │
│  │  #001  eth0  AA:BB:.. → CC:DD:..  IPv4    64 oct  ████  │   │
│  │  #002  eth0  FF:FF:.. → AA:BB:..  ARP     42 oct  ██    │   │
│  │  #003  eth0  CC:DD:.. → AA:BB:..  IPv6   128 oct  ████████│ │
│  │  (nouvelles trames qui défilent toutes les 800ms)       │   │
│  │                                                         │   │
│  │  [Cliquer sur une ligne → décompose la trame en détail] │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  DÉCOMPOSITION (apparaît au clic)                               │
│  ┌──────────────┬──────────────┬────────┬────────────────────┐  │
│  │  MAC DST     │  MAC SRC     │  TYPE  │  DONNÉES           │  │
│  │  6 octets    │  6 octets    │ 2 oct  │  N octets          │  │
│  │  AA:BB:CC:.. │  11:22:33:.. │ 0x0800 │  [IPv4...]         │  │
│  └──────────────┴──────────────┴────────┴────────────────────┘  │
│  (hover sur chaque case → tooltip avec explication du champ)    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module 1.2 — ARP Forge

**Ce que le terminal montre :** envoi d'un Request broadcast, réception d'un Reply avec la MAC.

**Visuel web :**

```
┌─────────────────────────────────────────────────────────────────┐
│  COUCHE 2 — ARP                                                 │
│                                                                 │
│  "Je connais l'IP de mon ami mais pas son numéro de porte.      │
│   Je crie dans le couloir : Qui habite au 192.168.1.50 ?"       │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                     SIMULATION ARP                        │  │
│  │                                                           │  │
│  │   [PC-A]──────────[SWITCH]──────────[PC-B]               │  │
│  │   192.168.1.10                      192.168.1.50          │  │
│  │                                                           │  │
│  │  IP cible : [192.168.1.50    ] [▶ Envoyer ARP Request]   │  │
│  │                                                           │  │
│  │  ① PC-A envoie : ══════════════════════════════►         │  │
│  │     ARP REQUEST  FF:FF:FF:FF:FF:FF (broadcast)            │  │
│  │     "Qui a 192.168.1.50 ?"                                │  │
│  │                                                           │  │
│  │  ② PC-B répond : ◄═══════════════════════════════        │  │
│  │     ARP REPLY  AA:BB:CC:DD:EE:50                          │  │
│  │     "C'est moi ! Ma MAC = AA:BB:CC:DD:EE:50"              │  │
│  │                                                           │  │
│  │  TABLE ARP de PC-A :                                      │  │
│  │  ┌──────────────────┬───────────────────┐                 │  │
│  │  │  192.168.1.50    │  AA:BB:CC:DD:EE:50│ ← nouveau !     │  │
│  │  └──────────────────┴───────────────────┘                 │  │
│  └───────────────────────────────────────────────────────────┘  │
│  (animation séquentielle : flèche 1 puis flèche 2 puis table)   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module 1.3 — Encapsulateur ★ (le plus riche visuellement)

**Ce que le terminal montre :** caractère → ASCII → hex → binaire, couches empilées, hexdump Wireshark, flux binaire coloré.

**Visuel web :**

```
┌─────────────────────────────────────────────────────────────────┐
│  TOUTES COUCHES — Encapsulation complète                        │
│                                                                 │
│  Message : [   Hello, réseau !         ]  IP dst : [192.168.1.1]│
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  VUE COUCHES (cliquer pour ouvrir/fermer)                 │  │
│  │                                                           │  │
│  │  ┌─ ETHERNET ─────────────────────────────────────────┐  │  │
│  │  │  MAC DST │ MAC SRC │ Type=0x0800                   │  │  │
│  │  │  ┌─ IPv4 ──────────────────────────────────────┐   │  │  │
│  │  │  │  TTL=64 │ Proto=17 │ src IP │ dst IP        │   │  │  │
│  │  │  │  ┌─ UDP ───────────────────────────────┐    │   │  │  │
│  │  │  │  │  src:12345 │ dst:80 │ len │ checksum│    │   │  │  │
│  │  │  │  │  ┌─ DONNÉES ──────────────────────┐ │    │   │  │  │
│  │  │  │  │  │  "Hello, réseau !"             │ │    │   │  │  │
│  │  │  │  │  └────────────────────────────────┘ │    │   │  │  │
│  │  │  │  └─────────────────────────────────────┘    │   │  │  │
│  │  │  └─────────────────────────────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─ HEXDUMP WIRESHARK ─────────────────────────────────────────┐ │
│  │  0000  AA BB CC DD EE 22 AA BB  CC DD EE 11 08 00 45 00     │ │
│  │  0010  00 28 12 34 00 00 40 11  E5 35 C0 A8 01 0A ...       │ │
│  │  (couleur rouge=Ethernet, vert=IP, orange=UDP, cyan=données)│ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌─ FLUX BINAIRE ──────────────────────────────────────────────┐ │
│  │  10101010 10111011 ... (rouge) | 01000101 ... (vert) | ...  │ │
│  │  [●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●]              │ │
│  │   ▲Ethernet (14)       ▲IP (20)  ▲UDP(8) ▲Données          │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module 2.1 — UDP Echo

**Ce que le terminal montre :** client envoie → serveur reçoit → écho renvoyé.

**Visuel web :**

```
┌─────────────────────────────────────────────────────────────────┐
│  COUCHE 4 — UDP  "La carte postale : rapide, sans garantie"     │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │   CLIENT              UDP               SERVEUR          │   │
│  │                                                          │   │
│  │   Message : [  Bonjour  ] [▶ Envoyer]                   │   │
│  │                                                          │   │
│  │   [CLIENT]  ──── datagramme ────►  [SERVEUR:9999]        │   │
│  │              "Bonjour"                                   │   │
│  │   [CLIENT]  ◄─── ECHO: Bonjour ───  [SERVEUR]           │   │
│  │                                                          │   │
│  │  ┌──────────────────────────────────────────────────┐   │   │
│  │  │  LOG (défile)                                    │   │   │
│  │  │  → Vous : Bonjour                                │   │   │
│  │  │  ← Serveur : ECHO: Bonjour                       │   │   │
│  │  └──────────────────────────────────────────────────┘   │   │
│  │                                                          │   │
│  │  Bouton [Simuler perte de paquet] → message sans écho    │   │
│  └──────────────────────────────────────────────────────────┘   │
│  Comparaison UDP vs TCP : tableau côte à côte                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module 2.2 — TCP Handshake

**Ce que le terminal montre :** SYN → SYN-ACK → ACK, puis échange de messages, puis FIN.

**Visuel web :**

```
┌─────────────────────────────────────────────────────────────────┐
│  COUCHE 4 — TCP  "L'appel téléphonique : on décroche avant      │
│                   de parler"                                    │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  CLIENT                                       SERVEUR   │   │
│  │    │                                             │       │   │
│  │    │──── SYN (seq=100) ─────────────────────────►│       │   │
│  │    │                                             │       │   │
│  │    │◄─── SYN-ACK (seq=200, ack=101) ─────────────│       │   │
│  │    │                                             │       │   │
│  │    │──── ACK (ack=201) ──────────────────────────►│       │   │
│  │    │                                             │       │   │
│  │    │════ CONNEXION ÉTABLIE ══════════════════════│       │   │
│  │    │                                             │       │   │
│  │    │──── DATA "Bonjour" ─────────────────────────►│       │   │
│  │    │◄─── ACK + "Reçu : Bonjour" ─────────────────│       │   │
│  │    │                                             │       │   │
│  │    │──── FIN ────────────────────────────────────►│       │   │
│  │    │◄─── ACK ────────────────────────────────────│       │   │
│  └──────────────────────────────────────────────────────────┘   │
│  (animation pas-à-pas : bouton [Étape suivante] ou [Auto])      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module 3.1 — Mini DNS

**Ce que le terminal montre :** QUERY → résultat ou NXDOMAIN.

**Visuel web :**

```
┌─────────────────────────────────────────────────────────────────┐
│  SERVICE — DNS  "L'annuaire d'Internet"                         │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  [monprojet.local         ] [▶ Résoudre]                 │   │
│  │                                                          │   │
│  │   NAVIGATEUR          DNS (port 5353)         RÉSULTAT   │   │
│  │       │                    │                     │       │   │
│  │       │── QUERY A ─────────►│                     │       │   │
│  │       │   "monprojet.local?"│                     │       │   │
│  │       │                    │ consulte la zone     │       │   │
│  │       │◄── ANSWER ──────────│                     │       │   │
│  │       │    192.168.50.10    │                     │       │   │
│  │                                                          │   │
│  │  ZONE DNS (table éditable)                               │   │
│  │  ┌─────────────────────────────────────────────────┐    │   │
│  │  │  monprojet.local  →  192.168.50.10  [supprimer] │    │   │
│  │  │  api.local        →  192.168.50.11  [supprimer] │    │   │
│  │  │  [+ Ajouter une entrée]                         │    │   │
│  │  └─────────────────────────────────────────────────┘    │   │
│  │                                                          │   │
│  │  PAQUET BINAIRE DNS (format RFC 1035)                    │   │
│  │  ┌──────┬───────┬─────────┬─────────────────────────┐   │   │
│  │  │  ID  │ FLAGS │ QDCOUNT │ Question: \x09monprojet\ │   │   │
│  │  └──────┴───────┴─────────┴─────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module 3.2 — Mini DHCP

**Ce que le terminal montre :** DISCOVER → OFFER avec pool d'IPs.

**Visuel web :**

```
┌─────────────────────────────────────────────────────────────────┐
│  SERVICE — DHCP  "L'accueil d'hôtel : je te donne une chambre"  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │   [▶ Simuler une nouvelle machine sur le réseau]         │   │
│  │                                                          │   │
│  │   NOUVEAU PC         DHCP SERVEUR        RÉSEAU          │   │
│  │       │                   │                 │            │   │
│  │       │─ DISCOVER ────────►│ (broadcast)     │            │   │
│  │       │  "Y a-t-il un serveur DHCP ?"        │            │   │
│  │       │◄─ OFFER ───────────│                 │            │   │
│  │       │  IP: 192.168.50.100 │                │            │   │
│  │       │                   │                 │            │   │
│  │  POOL D'ADRESSES :                                        │   │
│  │  [●] 192.168.50.100  ← attribuée (animation verte)        │   │
│  │  [○] 192.168.50.101  disponible                           │   │
│  │  [○] 192.168.50.102  disponible                           │   │
│  │  ... (20 cases visuelles)                                 │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module 4.1 — Serveur HTTP from Scratch

**Ce que le terminal montre :** requête GET parsée, réponse construite.

**Visuel web :**

```
┌─────────────────────────────────────────────────────────────────┐
│  COUCHE APP — HTTP  "Une page web = du texte dans un tuyau TCP" │
│                                                                 │
│  ┌────────────────────────────┬────────────────────────────┐    │
│  │  REQUÊTE (navigateur)      │  RÉPONSE (serveur)         │    │
│  │                            │                            │    │
│  │  GET /status HTTP/1.1      │  HTTP/1.1 200 OK           │    │
│  │  Host: localhost:8080      │  Content-Type: app/json    │    │
│  │  Accept: */*               │  Content-Length: 42        │    │
│  │  [ligne vide]              │  [ligne vide]              │    │
│  │                            │  {"status":"ok",...}       │    │
│  │                            │                            │    │
│  │  Route : [/status  ▼]      │  Code : [200 ●]            │    │
│  │  [▶ Envoyer la requête]    │                            │    │
│  └────────────────────────────┴────────────────────────────┘    │
│                                                                  │
│  ANATOMIE DES HEADERS (hover pour explication)                  │
│  ┌─────────────┬────────────────────────────────────────────┐   │
│  │  GET        │  méthode HTTP : lecture, sans corps        │   │
│  │  /status    │  chemin de la ressource demandée           │   │
│  │  HTTP/1.1   │  version du protocole                      │   │
│  │  Host:      │  obligatoire depuis HTTP/1.1               │   │
│  └─────────────┴────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module 4.2 — Proxy HTTP

**Ce que le terminal montre :** relay, log des requêtes, blocage liste noire.

**Visuel web :**

```
┌─────────────────────────────────────────────────────────────────┐
│  COUCHE APP — Proxy HTTP  "L'assistant silencieux"              │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  NAVIGATEUR ──────────► PROXY ──────────► SERVEUR WEB   │   │
│  │                         :8888                            │   │
│  │                                                          │   │
│  │  URL : [http://example.com/index.html]  [▶ Simuler]     │   │
│  │                                                          │   │
│  │  ① GET http://example.com/index.html HTTP/1.1  ──────►   │   │
│  │       (URL absolue = identifiant d'une requête proxiée)  │   │
│  │  ② PROXY extrait "example.com" et ouvre une connexion    │   │
│  │  ③ GET /index.html HTTP/1.1  ──────────────────────────► │   │
│  │  ④ 200 OK + HTML  ◄──────────────────────────────────    │   │
│  │  ⑤ 200 OK + HTML  ◄──────────────────────────────────    │   │
│  │                                                          │   │
│  │  LISTE NOIRE (éditable) :                                │   │
│  │  [pub.example.com] [×]   [+ Ajouter un site bloqué]     │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module 4.3 — Proxy HTTPS (CONNECT)

**Ce que le terminal montre :** HTTP direct vs tunnel aveugle CONNECT.

**Visuel web :**

```
┌─────────────────────────────────────────────────────────────────┐
│  COUCHE APP — Proxy HTTPS  "Le tuyau aveugle"                   │
│                                                                 │
│  ┌────────────────────────┬───────────────────────────────┐     │
│  │  HTTP (proxy lit tout) │  HTTPS (proxy aveugle)        │     │
│  │                        │                               │     │
│  │  CLIENT ─► PROXY ─► SITE│  CLIENT ──► PROXY ──► SITE  │     │
│  │  [GET /page ────────►]  │  [CONNECT site:443 ────────►]│     │
│  │  PROXY lit la requête   │  [200 Connection Established]│     │
│  │  PROXY voit le contenu  │  [████████ chiffré ████████] │     │
│  │                        │  PROXY ne voit que des bytes  │     │
│  │  Contenu visible ✓     │  Contenu invisible ✗ (TLS)   │     │
│  └────────────────────────┴───────────────────────────────┘     │
│                                                                  │
│  Animation : curseur sur "HTTP" → contenu déchiffré en vert     │
│              curseur sur "HTTPS" → contenu chiffré en rouge     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Détails techniques de la page

### Stack
- HTML + CSS + JS vanilla (zéro dépendance, un seul fichier)
- Pas de build, pas de bundler — ouvrir directement dans le navigateur

### Interactions communes à tous les modules
- Toutes les **flèches de protocole sont animées** (CSS transition + JS timeout)
- Tous les **champs de paquet ont un tooltip** au hover (même style que `packet_visualizer.html`)
- Bouton **"Pas-à-pas" / "Auto"** sur les modules avec séquences (TCP, ARP, DHCP)
- Champs de saisie pour les adresses IP/MAC/messages → reconstruction en temps réel du paquet

### Palette de couleurs (cohérente avec les scripts terminal)
| Couche | Couleur | Usage |
|---|---|---|
| Couche 2 Ethernet | `#0069d9` bleu | Badges, bordures |
| Couche 3 IP | `#218838` vert | Badges, bordures |
| Couche 4 Transport | `#e0a800` orange | Badges, bordures |
| Application / Données | `#6f42c1` violet | Badges, bordures |
| Binaire brut | `#0d1117` noir terminal | Fond hexdump |

### Fichier produit
```
bible_code/visualiseur_web.html   (~800-1000 lignes, tout-en-un)
```

---

## Prochaine étape

Valider ce plan → je code tout en une passe.
