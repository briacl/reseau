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
    """Génère une page HTML interactive pour visualiser l'encapsulation (Couches 1 à 4)."""
    clear_screen()
    print_header("GÉNÉRATEUR DE VISUALISATION WEB (AMÉLIORÉ)")
    print("Cette option va créer un fichier 'packet_visualizer.html' avec :")
    print(" - La Couche 1 (Physique/Bits)")
    print(" - Une représentation plus précise des en-têtes (Preamble, etc.)")
    print("\nParamètres de la démo (Alice -> Bob) :")
    print(" - Ethernet : MAC Src=AA:AA... -> MAC Dest=BB:BB...")
    print(" - IPv4     : IP Src=192.168.1.10 -> IP Dest=192.168.1.20")
    print(" - ICMP     : Echo Request (Ping)")
    
    input(f"\n{Colors.CYAN}[Appuyez sur Entrée pour générer et ouvrir...]{Colors.ENDC}")

    html_content = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Exploration des Couches Réseau</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; padding: 20px; text-align: center; color: #333; }
        h1 { margin-bottom: 5px; }
        .subtitle { color: #666; margin-bottom: 30px; }
        
        /* Conteneurs */
        .layer-box {
            border: 2px solid #ccc;
            border-radius: 6px;
            padding: 20px;
            margin: 15px auto;
            position: relative;
            background-color: white;
            box-shadow: 0 4px 10px rgba(0,0,0,0.05);
            text-align: left;
            transition: all 0.3s ease;
        }
        .layer-box:hover { box-shadow: 0 8px 15px rgba(0,0,0,0.15); transform: translateY(-2px); }

        /* Titres des couches */
        .layer-title {
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            color: white;
            font-size: 0.9em;
        }

        /* Styles spécifiques par couche */
        /* Couche 1 : Physique */
        .l1 { border-color: #343a40; background-color: #212529; color: #00ff00; font-family: 'Courier New', monospace; }
        .l1 .layer-title { background-color: #000; color: #00ff00; border: 1px solid #00ff00; }
        .bits-stream { word-break: break-all; opacity: 0.6; font-size: 0.8em; margin-bottom: 10px; }
        
        /* Couche 2 : Liaison (Ethernet) */
        .l2 { border-color: #007bff; background-color: #e3f2fd; color: #333; }
        .l2 .layer-title { background-color: #007bff; }

        /* Couche 3 : Réseau (IP) */
        .l3 { border-color: #28a745; background-color: #e8f5e9; }
        .l3 .layer-title { background-color: #28a745; }

        /* Couche 4/app : ICMP/Data */
        .l4 { border-color: #fd7e14; background-color: #fff3e0; }
        .l4 .layer-title { background-color: #fd7e14; }

        .data-box { border: 2px dashed #6c757d; background-color: #f8f9fa; padding: 10px; margin-top: 10px; color: #555; }
        
        /* Champs d'en-tête (style "tableau") */
        .header-row { display: flex; flex-wrap: wrap; gap: 2px; margin-bottom: 15px; }
        .field {
            flex: 1;
            min-width: 80px;
            background: white;
            border: 1px solid rgba(0,0,0,0.2);
            padding: 8px 5px;
            text-align: center;
            font-size: 0.85em;
            position: relative;
        }
        .field strong { display: block; font-size: 0.9em; margin-bottom: 2px; color: #000; }
        .field span { color: #555; }
        .field:hover { background-color: #fffde7; cursor: help; }

        /* Petits détails visuels */
        .preamble { background-color: #ccc; border-style: dashed; }
        .fcs { background-color: #ccc; border-style: dashed; }
        .arrow { text-align: center; color: #aaa; margin: 5px 0; font-size: 1.2em; }
        
        /* Info-bulle simple */
        .field[title]:hover::after {
            content: attr(title);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: #fff;
            padding: 5px;
            border-radius: 4px;
            font-size: 0.8em;
            white-space: nowrap;
            z-index: 10;
        }
    </style>
</head>
<body>

    <h1>Explorateur de Paquets : L'Encapsulation</h1>
    <p class="subtitle">Une vue en coupe du "Mille-feuille" réseau (Modèle OSI simplifié)</p>

    <!-- COUCHE 1 -->
    <div class="layer-box l1">
        <div class="layer-title">COUCHE 1 : PHYSIQUE (Le Câble)</div>
        <div style="margin-bottom: 10px; color: #bbb; font-size: 0.9em;">
            C'est ici que circulent les signaux électriques ou optiques. Pour l'ordinateur, c'est une suite de bits (0 et 1).
        </div>
        <div class="bits-stream">
            10101010 10101010 10101010 10101011 ... [Toute la trame ci-dessous est convertie en bits ici] ... 11001010
        </div>

        <!-- COUCHE 2 -->
        <div class="layer-box l2">
            <div class="layer-title">COUCHE 2 : LIAISON (Ethernet II)</div>
            
            <!-- En-tête Ethernet -->
            <div class="header-row">
                <div class="field preamble" title="7 octets de préambule pour la synchro + 1 octet SFD">
                    <strong>Preamble + SFD</strong>
                    <span>(Synchro)</span>
                </div>
                <div class="field" style="flex: 2;" title="Adresse MAC de Destination (6 octets)">
                    <strong>MAC Dest</strong>
                    <span>BB:BB:BB:BB:BB:BB</span>
                </div>
                <div class="field" style="flex: 2;" title="Adresse MAC Source (6 octets)">
                    <strong>MAC Src</strong>
                    <span>AA:AA:AA:AA:AA:AA</span>
                </div>
                <div class="field" title="Type de protocole encapsulé (0x0800 = IPv4)">
                    <strong>Type</strong>
                    <span>IPv4 (0x0800)</span>
                </div>
            </div>

            <div class="arrow">▼ Payload (Données) ▼</div>

            <!-- COUCHE 3 -->
            <div class="layer-box l3">
                <div class="layer-title">COUCHE 3 : RÉSEAU (IPv4)</div>
                
                <!-- En-tête IP -->
                <div class="header-row">
                    <div class="field" title="Version du protocole"><strong>Ver</strong><span>4</span></div>
                    <div class="field" title="Longueur de l'en-tête"><strong>IHL</strong><span>5</span></div>
                    <div class="field" title="Type of Service"><strong>TOS</strong><span>0</span></div>
                    <div class="field" title="Longueur totale du paquet"><strong>Len</strong><span>84</span></div>
                </div>
                <div class="header-row">
                    <div class="field" title="Identification pour réassemblage"><strong>ID</strong><span>12345</span></div>
                    <div class="field" title="Flags (Drapeaux)"><strong>Flags</strong><span>0</span></div>
                    <div class="field" title="Time To Live (Durée de vie)"><strong>TTL</strong><span>64</span></div>
                    <div class="field" title="Protocole supérieur (1=ICMP)"><strong>Proto</strong><span>1 (ICMP)</span></div>
                    <div class="field" title="Somme de contrôle de l'en-tête"><strong>Checksum</strong><span>0x....</span></div>
                </div>
                <div class="header-row">
                    <div class="field" style="flex:2; background-color:#e8f5e9; border-color:#28a745;">
                        <strong>IP Source</strong><br>192.168.1.10
                    </div>
                    <div class="field" style="flex:2; background-color:#e8f5e9; border-color:#28a745;">
                        <strong>IP Destination</strong><br>192.168.1.20
                    </div>
                </div>

                <div class="arrow">▼ Payload (Données) ▼</div>

                <!-- COUCHE 4 / APP -->
                <div class="layer-box l4">
                    <div class="layer-title">COUCHE "APP" : ICMP (Message)</div>
                    
                    <div class="header-row">
                        <div class="field" title="Type de message (8=Request)"><strong>Type</strong><span>8 (Echo Req)</span></div>
                        <div class="field" title="Code du message"><strong>Code</strong><span>0</span></div>
                        <div class="field" title="Vérification erreurs"><strong>Checksum</strong><span>0x1234</span></div>
                        <div class="field" title="Identifiant"><strong>ID</strong><span>1</span></div>
                        <div class="field" title="Numéro de séquence"><strong>Seq</strong><span>1</span></div>
                    </div>

                    <div class="data-box">
                        <strong>DATA (Contenu)</strong><br>
                        "Hello Bob!" <span style="color:#999; font-size:0.8em;">(32 octets de données...)</span>
                    </div>
                </div>
            </div>
            
            <div style="margin-top:20px; text-align:right;">
                <div class="field fcs" style="display:inline-block; width:150px;" title="Frame Check Sequence (CRC) pour vérifier l'intégrité de la trame">
                    <strong>FCS (CRC)</strong><br><span>(4 octets à la fin)</span>
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
