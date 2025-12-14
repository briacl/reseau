#!/usr/bin/env python3
"""
------------------------------------------------------------------------------------------------
 PACKET ADVENTURE : L'Explorateur de Paquets
------------------------------------------------------------------------------------------------
 Un programme pédagogique pour visualiser le fonctionnement des protocoles réseaux :
 - Ethernet II
 - ARP
 - IPv4
 - ICMP

 Auteur : Antigravity (Assistant AI)
 But : Permettre de comprendre "concrètement" la structure des paquets.
------------------------------------------------------------------------------------------------
"""

import time
import sys
import os
import webbrowser

# --- Configuration & Utilitaires ---

# Couleurs pour rendre ça plus joli (si le terminal le supporte)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Désactiver les couleurs si Windows sans support VT100 (facultatif, on suppose un terminal moderne)
if os.name == 'nt':
    os.system('color')

DELAY = 0.8  # Délai par défaut pour la lecture

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(text, delay=0.01, end='\n'):
    """Affiche le texte lettre par lettre (ou presque) pour un effet narratif."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        # time.sleep(delay) # Commenté pour ne pas être trop lent en débug, décommenter pour l'effet "RPG"
    print(end=end)
    # time.sleep(0.3) 

def print_header(title):
    print(f"\n{Colors.HEADER}{'='*60}")
    print(f" {title.center(58)}")
    print(f"{'='*60}{Colors.ENDC}\n")

def pause():
    input(f"\n{Colors.CYAN}[Appuyez sur Entrée pour continuer...]{Colors.ENDC}")

# --- Fonctions de Dessin de Paquets ---

def draw_ethernet(dst, src, etype, payload_desc="...Données..."):
    """Dessine l'en-tête Ethernet II."""
    print(f"{Colors.BOLD}--- TRAME ETHERNET II ---{Colors.ENDC}")
    print(f"La trame est l'enveloppe physique qui transporte tout.")
    print(f"+" + "-"*20 + "+" + "-"*20 + "+" + "-"*12 + "+" + "-"*23 + "+")
    print(f"| {Colors.GREEN}DEST MAC{Colors.ENDC}           | {Colors.BLUE}SRC MAC{Colors.ENDC}            | {Colors.WARNING}TYPE{Colors.ENDC}       | DONNÉES / FCS (CRC)     |")
    print(f"+" + "-"*20 + "+" + "-"*20 + "+" + "-"*12 + "+" + "-"*23 + "+")
    print(f"| {dst:<18} | {src:<18} | {etype:<10} | {payload_desc:<21} |")
    print(f"+" + "-"*20 + "+" + "-"*20 + "+" + "-"*12 + "+" + "-"*23 + "+")
    print(f"{Colors.GREEN}DEST MAC{Colors.ENDC} : Adresse physique du prochain saut (Destination).")
    print(f"{Colors.BLUE}SRC MAC{Colors.ENDC}  : Mon adresse physique (Source).")
    print(f"{Colors.WARNING}TYPE{Colors.ENDC}     : Ce qu'il y a dedans (ex: 0x0800 pour IPv4, 0x0806 pour ARP).")
    print(f"FCS      : Frame Check Sequence (CRC) pour vérifier les erreurs (souvent géré par la carte réseau).")

def draw_arp(opcode, src_mac, src_ip, dst_mac, dst_ip):
    """Dessine un paquet ARP."""
    op_str = "REQUEST (1)" if opcode == 1 else "REPLY (2)"
    title = "ARP REQUEST (Qui est cet IP ?)" if opcode == 1 else "ARP REPLY (C'est moi !)"
    
    print(f"{Colors.BOLD}--- PAQUET ARP ({title}) ---{Colors.ENDC}")
    print("ARP sert à trouver l'adresse MAC correspondant à une IP connue.")
    print("+" + "-"*40 + "+")
    print(f"| Hardware Type (Eth=1) | Protocol Type (IP)   |")
    print("+" + "-"*40 + "+")
    print(f"| Hlen=6 | Plen=4       | {Colors.WARNING}Opcode = {opcode} ({op_str}){Colors.ENDC}|")
    print("+" + "-"*40 + "+")
    print(f"| {Colors.BLUE}Sender MAC: {src_mac:<26}{Colors.ENDC} |")
    print(f"| {Colors.BLUE}Sender IP : {src_ip:<26}{Colors.ENDC} |")
    print("+" + "-"*40 + "+")
    print(f"| {Colors.GREEN}Target MAC: {dst_mac:<26}{Colors.ENDC} |")
    print(f"| {Colors.GREEN}Target IP : {dst_ip:<26}{Colors.ENDC} |")
    print("+" + "-"*40 + "+")

def draw_ipv4(src_ip, dst_ip, proto, length, identification, payload_desc="..."):
    """Dessine un en-tête IPv4."""
    proto_str = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))
    
    print(f"{Colors.BOLD}--- PAQUET IPv4 ---{Colors.ENDC}")
    print("Le paquet IP gère l'adressage logique et le routage sur Internet.")
    # On simplifie un peu l'affichage pour la clarté (largeur fixe 32 bits simulée)
    print("+" + "-"*14 + "+" + "-"*12 + "+" + "-"*12 + "+" + "-"*18 + "+")
    print("| Ver=4 | IHL=5  | TOS          | Total Length={:<6} |".format(length))
    print("+" + "-"*14 + "+" + "-"*12 + "+" + "-"*12 + "+" + "-"*18 + "+")
    print("| Identification = {:<13} | Flgs | Frag Offset    |".format(identification))
    print("+" + "-"*14 + "+" + "-"*12 + "+" + "-"*32 + "+")
    print("| TTL   | {0}Proto={1:<3}{2} | Checksum     | {3}SOURCE IP{2}                      |".format(Colors.WARNING, proto, Colors.ENDC, Colors.BLUE))
    print("|       | {0:<7}    |              | {1:<30} |".format(proto_str, src_ip))
    print("+" + "-"*14 + "+" + "-"*12 + "+" + "-"*32 + "+")
    print("| {0}DESTINATION IP{1}                   | Options / Padding              |".format(Colors.GREEN, Colors.ENDC))
    print("| {0:<30} |                                |".format(dst_ip))
    print("+" + "-"*30 + "+" + "-"*28 + "+")
    print(f"| DONNÉES ({payload_desc}) ...")
    print("+" + "-"*60 + "+")

def draw_icmp(itype, code, checksum, data):
    """Dessine un en-tête ICMP."""
    type_desc = {8: "ECHO REQUEST (Ping)", 0: "ECHO REPLY (Pong)", 3: "DEST UNREACHABLE"}.get(itype, "Autre")
    
    print(f"{Colors.BOLD}--- MESSAGE ICMP ---{Colors.ENDC}")
    print("ICMP est le 'messager' du réseau, utilisé pour le diagnostic (Ping) et les erreurs.")
    print("+" + "-"*15 + "+" + "-"*15 + "+" + "-"*28 + "+")
    print(f"| {Colors.WARNING}TYPE = {itype:<5}{Colors.ENDC}  | CODE = {code:<5}  | Checksum = {checksum:<15}   |")
    print("+" + "-"*15 + "+" + "-"*15 + "+" + "-"*28 + "+")
    print(f"| Identificateur (ID)             | Numéro de Séquence (Seq)     |")
    print("+" + "-"*60 + "+")
    print(f"| DONNÉES : {data:<51} |")
    print("+" + "-"*60 + "+")
    print(f" -> Ce message est de type : {Colors.BOLD}{type_desc}{Colors.ENDC}")

# --- Modes de Simulation ---

def explain_ethernet():
    clear_screen()
    print_header("Exploration : En-tête ETHERNET II")
    slow_print("Imaginez Ethernet comme une enveloppe physique que les facteurs (les switchs) utilisent")
    slow_print("pour livrer le courrier dans un même bâtiment (le réseau local).\n")
    
    src = "00:AA:BB:CC:DD:11"
    dst = "00:AA:BB:CC:DD:22"
    etype = "0x0800"
    
    draw_ethernet(dst, src, etype, "Paquet IP...")
    
    print("\nDétails importants :")
    print(f"1. {Colors.BOLD}MAC Destination :{Colors.ENDC} C'est le plus important ! Les switchs regardent ÇA pour savoir où envoyer.")
    print(f"2. {Colors.BOLD}MAC Source :{Colors.ENDC} C'est l'expéditeur. Les switchs l'utilisent pour APPRENDRE où vous êtes.")
    print(f"3. {Colors.BOLD}Type :{Colors.ENDC} Indique au récepteur à qui donner le paquet une fois l'enveloppe ouverte (0x0800 = IPv4, 0x0806 = ARP).")
    print(f"4. {Colors.BOLD}FCS (CRC) :{Colors.ENDC} Une somme de contrôle à la fin (non montrée ici en détail) pour vérifier que le paquet n'est pas abimé.")
    pause()

def explain_arp():
    clear_screen()
    print_header("Exploration : Protocole ARP")
    slow_print("ARP (Address Resolution Protocol) est le détective du réseau local.")
    slow_print("Problème : Je connais l'IP de mon ami (ex: 192.168.1.50) mais je ne peux pas envoyer de trame Ethernet")
    slow_print("sans connaître son adresse MAC physique !\n")

    slow_print(f"{Colors.CYAN}--- ÉTAPE 1 : ARP REQUEST (Le Cri) ---{Colors.ENDC}")
    slow_print("Je crie à tout le monde (Broadcast MAC FF:FF:FF:FF:FF:FF) : 'QUI A l'IP 192.168.1.50 ?'")
    
    draw_ethernet("FF:FF:FF:FF:FF:FF", "MA_MAC_A", "0x0806", "ARP Request")
    draw_arp(1, "MA_MAC_A", "192.168.1.10", "00:00:00:00:00:00", "192.168.1.50")
    
    pause()
    print(f"\n{Colors.CYAN}--- ÉTAPE 2 : ARP REPLY (La Réponse) ---{Colors.ENDC}")
    slow_print("Seul 192.168.1.50 répond : 'C'est moi ! Voici ma carte d'identité (MAC).'")
    
    draw_ethernet("MA_MAC_A", "SA_MAC_B", "0x0806", "ARP Reply")
    draw_arp(2, "SA_MAC_B", "192.168.1.50", "MA_MAC_A", "192.168.1.10")
    
    slow_print("\nMaintenant, l'ordinateur A connaît la MAC de B et peut l'enregistrer dans sa table ARP ('cache ARP').")
    pause()

def explain_ipv4():
    clear_screen()
    print_header("Exploration : En-tête IPv4")
    slow_print("IPv4 est le système d'adressage global. C'est comme une adresse postale (Pays, Ville, Rue).")
    slow_print("Contrairement à Ethernet (local), le paquet IP reste intact de bout en bout (généralement).")
    
    print()
    draw_ipv4("192.168.1.10", "8.8.8.8", 1, 84, 12345, "ICMP Ping")
    
    print("\nPoints Clés :")
    print(f"- {Colors.BOLD}TTL (Time To Live){Colors.ENDC} : Un compteur de survie. Diminue de 1 à chaque routeur traversé. À 0, le paquet meurt (évite les boucles infinies).")
    print(f"- {Colors.BOLD}Protocol{Colors.ENDC} : Comme le champ 'Type' d'Ethernet. Dit à l'IP quoi faire du contenu (1=ICMP, 6=TCP, 17=UDP).")
    print(f"- {Colors.BOLD}Source / Dest IP{Colors.ENDC} : Adresses logiques finales.")
    pause()

def explain_icmp():
    clear_screen()
    print_header("Exploration : ICMP")
    slow_print("ICMP (Internet Control Message Protocol) n'envoie pas de données utilisateur (comme une page web).")
    slow_print("C'est un outil de maintenance. L'exemple le plus connu est le PING.")
    
    print()
    slow_print(f"{Colors.BOLD}Exemple : PING (Echo Request){Colors.ENDC}")
    draw_icmp(8, 0, "0x4D2E", "abcdefghijklmnopqrstuvw...")
    
    print()
    slow_print(f"{Colors.BOLD}Exemple : PONG (Echo Reply){Colors.ENDC}")
    draw_icmp(0, 0, "0x55EE", "abcdefghijklmnopqrstuvw...")
    
    print("\nNote : ICMP est encapsulé DANS IP. Donc un Ping c'est :")
    print("[ Ethernet [ IPv4 [ ICMP [ Données ] ] ] ]")
    pause()

def generate_web_visualization():
    """Génère une page HTML interactive avec infobulles, layout précis et Titres de Couches."""
    clear_screen()
    print_header("GÉNÉRATEUR DE VISUALISATION INTERACTIVE (V4)")
    print("Cette option va créer un fichier 'packet_visualizer.html'.")
    print(" - Layout IPv4 standard (lignes précis)")
    print(" - Infobulles au survol souris (Tooltips)")
    print(" - Titres des Couches (1, 2, 3, 4) rétablis")
    
    input(f"\n{Colors.CYAN}[Appuyez sur Entrée pour générer et ouvrir...]{Colors.ENDC}")

    html_content = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Explorateur Interactif de Paquets</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; padding: 20px; color: #333; }
        h1 { text-align: center; margin-bottom: 5px; }
        .subtitle { text-align: center; color: #666; margin-bottom: 30px; }

        .container { max-width: 1000px; margin: 0 auto; }

        /* --- TITRES DES COUCHES (Badge Style) --- */
        .layer-badge-row {
            margin-bottom: 5px;
            margin-top: 15px;
            text-align: left;
        }
        .layer-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .badge-l1 { background-color: #222; border: 1px solid #444; color: #0f0; }
        .badge-l2 { background-color: #0069d9; }
        .badge-l3 { background-color: #218838; }
        .badge-l4 { background-color: #e0a800; color: #333; }

        /* --- TABS / BARRES --- */
        .section-bar {
            display: flex;
            margin-bottom: 5px;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            cursor: pointer;
            transition: transform 0.1s;
        }
        .section-bar:hover { transform: scale(1.002); }

        .section-tab {
            flex: 1;
            padding: 10px 15px;
            background-color: #eee;
            border-right: 1px solid #ddd;
            font-weight: bold;
            display: flex;
            align-items: center;
            justify-content: space-between;
            user-select: none;
            font-size: 0.95em;
        }
        .section-tab:last-child { border-right: none; }
        .section-tab:hover { filter: brightness(0.95); }
        .caret { transition: transform 0.3s; font-size: 0.8em; }
        .rotated { transform: rotate(180deg); }

        /* Couleurs */
        .eth-header-tab { background-color: #007bff; color: white; }
        .eth-payload-tab { background-color: #b3d7ff; color: #004085; }
        .eth-trailer-tab { background-color: #0056b3; color: white; }

        .ip-header-tab { background-color: #28a745; color: white; }
        .ip-payload-tab { background-color: #c3e6cb; color: #155724; }

        .icmp-header-tab { background-color: #fd7e14; color: white; }
        .icmp-data-tab { background-color: #ffeeba; color: #856404; }

        /* --- PANNEAUX DÉTAILS --- */
        .details-panel {
            display: none;
            padding: 20px;
            background-color: white;
            border: 1px solid #ddd;
            border-top: none;
            margin-bottom: 20px;
            border-radius: 0 0 6px 6px;
            animation: fadeIn 0.3s;
        }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        /* --- GRILLES ET CHAMPS --- */
        .packet-row {
            display: flex;
            margin-bottom: -1px;
        }
        .field-box {
            flex: 1;
            border: 1px solid #999;
            padding: 8px 5px;
            text-align: center;
            background: #fafafa;
            position: relative;
            min-width: 0;
        }
        .field-box:hover {
            background-color: #fffde7;
            z-index: 2;
            cursor: help;
        }
        
        .field-label { display: block; font-size: 0.7em; color: #666; text-transform: uppercase; margin-bottom: 3px; }
        .field-value { font-weight: bold; font-size: 0.9em; word-wrap: break-word; }

        /* Infobulles (Tooltips) */
        .field-box[title]:hover::after {
            content: attr(title);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: #fff;
            padding: 6px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            white-space: nowrap;
            z-index: 100;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            pointer-events: none;
        }
        .field-box[title]:hover::before {
            content: '';
            position: absolute;
            bottom: 100%;
            left: 50%;
            margin-bottom: -5px;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: #333 transparent transparent transparent;
            z-index: 100;
        }

        /* Couche Physique */
        .physical-layer {
            background-color: #222;
            color: #0f0;
            padding: 10px;
            font-family: monospace;
            border-radius: 6px;
            margin-bottom: 20px;
            overflow-x: hidden;
            white-space: nowrap;
            border: 2px solid #555;
            text-align: left;
        }
    </style>
    <script>
        function toggle(id, caretId) {
            var panel = document.getElementById(id);
            var caret = document.getElementById(caretId);
            if (panel.style.display === "block") {
                panel.style.display = "none";
                caret.classList.remove("rotated");
            } else {
                panel.style.display = "block";
                caret.classList.add("rotated");
            }
        }
    </script>
</head>
<body>

    <h1>Visualiseur Réseau (V4)</h1>
    <p class="subtitle">Survolez les cases pour voir les explications. Cliquez sur les barres pour ouvrir/fermer.</p>

    <div class="container">
        
        <!-- LAYER 1 -->
        <div class="layer-badge-row"><span class="layer-badge badge-l1">Couche 1 : Physique</span></div>
        <div title="Couche Physique : Transmission des bits sur le support">
            <div class="physical-layer">
                Signal : 10101010 10101010 10101010 ... [ Préambule + SFD + Trame Ethernet ] ...
            </div>
        </div>

        <!-- LAYER 2 WRAPPER -->
        <div class="layer-badge-row"><span class="layer-badge badge-l2">Couche 2 : Liaison (Ethernet II)</span></div>
        <div class="layer-wrapper">
            <!-- TABS ETHERNET -->
            <div class="section-bar">
                <div class="section-tab eth-header-tab" onclick="toggle('eth-head', 'c1')">
                    <span>1. ETHERNET HEADER</span> <span id="c1" class="caret">▼</span>
                </div>
                <div class="section-tab eth-payload-tab" onclick="toggle('eth-pay', 'c2')">
                    <span>2. ETHERNET PAYLOAD (IPv4)</span> <span id="c2" class="caret">▼</span>
                </div>
                <div class="section-tab eth-trailer-tab" onclick="toggle('eth-trail', 'c3')">
                    <span>3. TRAILER</span> <span id="c3" class="caret">▼</span>
                </div>
            </div>

            <!-- DETAIL ETHERNET HEADER -->
            <div id="eth-head" class="details-panel">
                <h3>En-tête Ethernet II</h3>
                <div class="packet-row">
                    <div class="field-box" style="flex:2" title="7 octets de préambule + 1 octet SFD pour synchroniser l'horloge"><span class="field-label">Préambule</span>1010...</div>
                    <div class="field-box" style="flex:3" title="Adresse MAC du destinataire (6 octets)"><span class="field-label">MAC Dest</span>BB:BB:BB:BB:BB:BB</div>
                    <div class="field-box" style="flex:3" title="Adresse MAC de l'émetteur (6 octets)"><span class="field-label">MAC Src</span>AA:AA:AA:AA:AA:AA</div>
                    <div class="field-box" style="flex:1" title="Type de protocole contenu (0x0800 = IPv4)"><span class="field-label">Type</span>0x0800</div>
                </div>
            </div>

            <!-- DETAIL ETHERNET TRAILER -->
            <div id="eth-trail" class="details-panel">
                <h3>Queue de Trame</h3>
                <div class="packet-row">
                    <div class="field-box" title="Frame Check Sequence (CRC32) : Permet de détecter les erreurs de transmission"><span class="field-label">FCS</span>0xA1B2C3D4</div>
                </div>
            </div>

            <!-- DETAIL ETHERNET PAYLOAD (IPv4) -->
            <div id="eth-pay" class="details-panel" style="background-color:#f9f9f9;">
                
                <div class="layer-badge-row"><span class="layer-badge badge-l3">Couche 3 : Réseau (IPv4)</span></div>

                <!-- TABS IPv4 -->
                <div class="section-bar">
                    <div class="section-tab ip-header-tab" onclick="toggle('ip-head', 'c4')">
                        <span>IPv4 HEADER (RFC 791)</span> <span id="c4" class="caret">▼</span>
                    </div>
                    <div class="section-tab ip-payload-tab" onclick="toggle('ip-pay', 'c5')">
                        <span>IPv4 DATA (ICMP)</span> <span id="c5" class="caret">▼</span>
                    </div>
                </div>

                <!-- DETAIL IPv4 HEADER (Strict Layout) -->
                <div id="ip-head" class="details-panel">
                    <h3>En-tête IPv4 (20 Octets)</h3>
                    
                    <!-- Ligne 1 -->
                    <div class="packet-row">
                        <div class="field-box" title="Version du protocole IP (4 bits)"><span class="field-label">Version</span>4</div>
                        <div class="field-box" title="Header Length (4 bits) : Nombre de mots de 32 bits (5 min)"><span class="field-label">IHL</span>5</div>
                        <div class="field-box" title="Type of Service (8 bits)"><span class="field-label">TOS</span>0</div>
                        <div class="field-box" title="Longueur totale du paquet en octets (16 bits)"><span class="field-label">Total Length</span>84</div>
                    </div>
                    <!-- Ligne 2 -->
                    <div class="packet-row">
                        <div class="field-box" title="Identification (16 bits) : Pour reconstituer les fragments"><span class="field-label">Identification</span>12345</div>
                        <div class="field-box" title="Flags (3 bits) : Dont Fragment, More Fragments..."><span class="field-label">Flags</span>0</div>
                        <div class="field-box" title="Fragment Offset (13 bits) : Position du fragment"><span class="field-label">Frag Offset</span>0</div>
                    </div>
                    <!-- Ligne 3 -->
                    <div class="packet-row">
                        <div class="field-box" title="Time To Live (8 bits) : Décrémenté à chaque routeur"><span class="field-label">TTL</span>64</div>
                        <div class="field-box" title="Protocol (8 bits) : 1=ICMP, 6=TCP, 17=UDP"><span class="field-label">Protocol</span>1 (ICMP)</div>
                        <div class="field-box" style="flex:2" title="Header Checksum (16 bits) : Vérifie l'en-tête IP"><span class="field-label">Checksum</span>0x....</div>
                    </div>
                    <!-- Ligne 4 -->
                    <div class="packet-row">
                        <div class="field-box" style="background:#e8f5e9" title="Adresse IP Source (32 bits)"><span class="field-label">Source IP Address</span>192.168.1.10</div>
                    </div>
                    <!-- Ligne 5 -->
                    <div class="packet-row">
                        <div class="field-box" style="background:#e8f5e9" title="Adresse IP Destination (32 bits)"><span class="field-label">Destination IP Address</span>192.168.1.20</div>
                    </div>
                </div>

                <!-- DETAIL IPv4 PAYLOAD (ICMP) -->
                <div id="ip-pay" class="details-panel" style="background-color:#fff;">
                    
                    <div class="layer-badge-row"><span class="layer-badge badge-l4">Couche 4/App : Application (ICMP)</span></div>

                    <!-- TABS ICMP -->
                    <div class="section-bar">
                        <div class="section-tab icmp-header-tab" onclick="toggle('icmp-head', 'c6')">
                            <span>ICMP HEADER</span> <span id="c6" class="caret">▼</span>
                        </div>
                        <div class="section-tab icmp-data-tab" onclick="toggle('icmp-data', 'c7')">
                            <span>ICMP DATA</span> <span id="c7" class="caret">▼</span>
                        </div>
                    </div>

                    <div id="icmp-head" class="details-panel">
                        <h3>En-tête ICMP</h3>
                        <div class="packet-row">
                            <div class="field-box" title="Type de message (ex: 8 pour Echo Request)"><span class="field-label">Type</span>8</div>
                            <div class="field-box" title="Code (Sous-type)"><span class="field-label">Code</span>0</div>
                            <div class="field-box" title="Checksum ICMP"><span class="field-label">Checksum</span>0x1234</div>
                        </div>
                        <div class="packet-row">
                            <div class="field-box" title="Identifiant (pour appairer req/rep)"><span class="field-label">Identifier</span>1</div>
                            <div class="field-box" title="Numéro de séquence"><span class="field-label">Seq Number</span>1</div>
                        </div>
                    </div>

                    <div id="icmp-data" class="details-panel">
                        <h3>Données</h3>
                        <div style="padding:10px; border:1px dashed #ccc; background:#fdfdfd; font-family:monospace;">
                            payload = "Hello Bob!"
                        </div>
                    </div>

                </div>

            </div>
        </div>

    </div>

</body>
</html>
"""
    
    file_path = os.path.abspath("packet_visualizer.html")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"\n{Colors.GREEN}Fichier généré : {file_path}{Colors.ENDC}")
    print("Ouverture du navigateur...")
    webbrowser.open('file://' + file_path)
    time.sleep(1)

def simulation_ping():
    clear_screen()
    print_header("SIMULATION COMPLÈTE : Un PING de A vers B")
    
    # Données
    ip_a = "192.168.1.10"
    mac_a = "AA:AA:AA:AA:AA:AA"
    ip_b = "192.168.1.20"
    mac_b = "BB:BB:BB:BB:BB:BB"
    
    print(f"Situation : {Colors.BLUE}Alice (A){Colors.ENDC} veut pinger {Colors.GREEN}Bob (B){Colors.ENDC}.")
    print(f"Alice : {ip_a} ({mac_a})")
    print(f"Bob   : {ip_b} ({mac_b}) (Inconnu dans la table ARP d'Alice pour l'instant)")
    pause()
    
    # 1. Construction ICMP
    clear_screen()
    print_header("1. La couche Application demande un PING")
    slow_print("Alice crée un message ICMP Echo Request.")
    draw_icmp(8, 0, "0x1234", "Hello Bob!")
    print("\nCe message est passé à la couche IP.")
    pause()
    
    # 2. Encapsulation IP
    clear_screen()
    print_header("2. La couche IP ajoute son en-tête")
    slow_print("Alice encapsule l'ICMP dans un paquet IPv4.")
    slow_print(f"Source: {ip_a}, Destination: {ip_b}, Protocol: 1 (ICMP)")
    draw_ipv4(ip_a, ip_b, 1, 64, 555, "ICMP Header + Data")
    print("\nLe paquet IP est prêt. Il doit être envoyé sur le réseau local.")
    pause()
    
    # 3. Résolution ARP
    clear_screen()
    print_header("3. Problème de la couche Liaison (Ethernet)")
    slow_print("Le driver réseau veut créer la trame Ethernet.")
    print(f"MAC Source : {mac_a} (C'est nous)")
    print(f"MAC Dest   : ??? (On connait 192.168.1.20 mais pas sa MAC !)")
    print(f"\n{Colors.WARNING}>> ALERTE : ARP NÉCESSAIRE ! <<{Colors.ENDC}")
    print("Alice met le paquet IP en attente et lance une requête ARP.")
    pause()
    
    # Simulation ARP rapide
    print("\n[Simulation ARP]")
    print(f"Alice crie : 'Qui est {ip_b} ?'")
    draw_ethernet("FF:FF:FF:FF:FF:FF", mac_a, "0x0806", "ARP Request")
    time.sleep(1)
    print(f"\nBob répond : 'C'est moi, ma MAC est {mac_b}'")
    draw_ethernet(mac_a, mac_b, "0x0806", "ARP Reply")
    time.sleep(1)
    print(f"\n{Colors.GREEN}>> MAC de Bob ({mac_b}) apprise ! <<{Colors.ENDC}")
    pause()
    
    # 4. Encapsulation Ethernet finale
    clear_screen()
    print_header("4. Envoi du paquet IP (enfin !)")
    slow_print("Maintenant qu'on a la MAC de Bob, on peut encapsuler le paquet IP.")
    draw_ethernet(mac_b, mac_a, "0x0800", "Paquet IPv4 (contient ICMP)")
    print("\nLa trame part sur le câble... Zzzzzzip !")
    pause()
    
    # 5. Réception
    clear_screen()
    print_header("5. Réception chez Bob")
    slow_print("Bob reçoit la trame.")
    print("1. Vérifie MAC Dest (C'est bien BB:BB...) -> OK, j'ouvre.")
    print("2. Regarde Type (0x0800) -> C'est de l'IP, je passe à la couche IP.")
    print("3. Vérifie IP Dest (192.168.1.20) -> C'est bien moi, j'ouvre.")
    print("4. Regarde Protocole (1) -> C'est de l'ICMP.")
    print(f"5. Lit le message ICMP : '{Colors.BOLD}ECHO REQUEST{Colors.ENDC}'")
    print("\nBob dit : 'Ah, Alice me ping ! Je dois répondre PONG.'")
    pause()
    
    print("\n--- Et le processus inverse recommence pour la réponse ! ---")
    print("C'est ainsi que fonctionnent vos réseaux tous les jours.")
    pause()

def main_menu():
    while True:
        clear_screen()
        print_header("MENU PRINCIPAL - PACKET ADVENTURE")
        print("1. Comprendre l'en-tête ETHERNET II")
        print("2. Comprendre le protocole ARP")
        print("3. Comprendre le paquet IPv4")
        print("4. Comprendre ICMP")
        print(f"5. {Colors.GREEN}Lancer la Simulation GUIDÉE (L'Aventure){Colors.ENDC}")
        print(f"6. {Colors.CYAN}Générer une visualisation Web (HTML){Colors.ENDC}")
        print("Q. Quitter")
        
        choice = input("\nVotre choix : ").strip().upper()
        
        if choice == '1':
            explain_ethernet()
        elif choice == '2':
            explain_arp()
        elif choice == '3':
            explain_ipv4()
        elif choice == '4':
            explain_icmp()
        elif choice == '5':
            simulation_ping()
        elif choice == '6':
            generate_web_visualization()
        elif choice == 'Q':
            print("\nAu revoir et bonne route sur les réseaux !")
            break
        else:
            print("Choix invalide.")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nInterruption... Au revoir !")
        sys.exit(0)
