#!/usr/bin/env python3
import os
import subprocess
import sys

# --- Configuration ---
INTERFACE = "eth0"
DEFAULT_MASK = "/24"

# --- Colors ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def get_current_ips():
    """Récupère la liste des IPs actuelles sur l'interface."""
    try:
        res = subprocess.check_output(["ip", "-4", "addr", "show", INTERFACE]).decode("utf-8")
        ips = []
        for line in res.splitlines():
            if "inet " in line:
                parts = line.split()
                ip_cidr = parts[1]
                ips.append(ip_cidr)
        return ips
    except subprocess.CalledProcessError:
        print(f"{Colors.FAIL}Erreur: Impossible de lire les IPs de {INTERFACE}{Colors.ENDC}")
        return []

def add_ip(ip_address):
    if "/" not in ip_address:
        ip_address += DEFAULT_MASK
    
    print(f"\nAjout de l'IP {Colors.GREEN}{ip_address}{Colors.ENDC} sur {INTERFACE}...")
    cmd = ["sudo", "ip", "addr", "add", ip_address, "dev", INTERFACE]
    try:
        subprocess.check_call(cmd)
        print(f"{Colors.GREEN}Succès !{Colors.ENDC}")
    except subprocess.CalledProcessError:
        print(f"{Colors.FAIL}Erreur lors de l'ajout de l'IP.{Colors.ENDC}")

def remove_ip(ip_address):
    # Si l'utilisateur a oublié le masque mais que l'IP existe, on essaie de deviner ou on passe sans masque (ip addr del est flexible parfois, mais mieux vaut être précis)
    # Pour simplifier, on demande à l'utilisateur de choisir dans la liste
    pass

def managed_remove_ip(ip_cidr):
    print(f"\nSuppression de l'IP {Colors.WARNING}{ip_cidr}{Colors.ENDC} de {INTERFACE}...")
    cmd = ["sudo", "ip", "addr", "del", ip_cidr, "dev", INTERFACE]
    try:
        subprocess.check_call(cmd)
        print(f"{Colors.GREEN}Succès !{Colors.ENDC}")
    except subprocess.CalledProcessError:
        print(f"{Colors.FAIL}Erreur lors de la suppression de l'IP.{Colors.ENDC}")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_wsl_ip():
    """Récupère l'IP principale WSL (celle en 172.x)."""
    try:
        res = subprocess.check_output(["ip", "-4", "addr", "show", "eth0"]).decode("utf-8")
        for line in res.splitlines():
            if "inet " in line and "172." in line: # Filtre un peu grossier mais efficace pour WSL par défaut
                return line.split()[1].split('/')[0]
        # Fallback si pas de 172
        for line in res.splitlines():
            if "inet " in line:
                return line.split()[1].split('/')[0]
    except:
        pass
    return None

def add_port_forwarding(port):
    wsl_ip = get_wsl_ip()
    if not wsl_ip:
        print(f"{Colors.FAIL}Impossible de trouver l'IP WSL.{Colors.ENDC}")
        return

    print(f"\nConfiguration du PONT Windows -> WSL ({wsl_ip}) sur le port {port}...")
    print("Une fenêtre 'Administrateur' Windows va peut-être s'ouvrir pour confirmer.")

    # Commande complexe PowerShell pour :
    # 1. Ajouter le Proxy (netsh)
    # 2. Ouvrir le Pare-feu (New-NetFirewallRule)
    ps_script = f"""
    netsh interface portproxy add v4tov4 listenport={port} listenaddress=0.0.0.0 connectport={port} connectaddress={wsl_ip};
    New-NetFirewallRule -DisplayName "WSL Bridge Port {port}" -Direction Inbound -LocalPort {port} -Protocol TCP -Action Allow -ErrorAction SilentlyContinue;
    Write-Host "Pont créé avec succès !";
    Pause;
    """
    
    ps_path = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    if not os.path.exists(ps_path):
        ps_path = "powershell.exe" # Fallback if standard path fails

    # Encodage de la commande pour passer proprement dans l'argument
    # On utilise Start-Process pour élever les privilèges (RunAs)
    cmd = [
        ps_path, 
        "-Command", 
        f"Start-Process powershell -Verb RunAs -ArgumentList '-NoExit', '-Command', '{ps_script}'"
    ]
    
    try:
        subprocess.call(cmd)
        print(f"{Colors.GREEN}Commande envoyée à Windows.{Colors.ENDC}")
    except FileNotFoundError:
        print(f"{Colors.FAIL}Erreur: powershell.exe introuvable (ni dans le PATH ni dans {ps_path}).{Colors.ENDC}")
        print(f"{Colors.WARNING}Verifiez que vous avez accès aux exécutables Windows depuis WSL (interop enabled).{Colors.ENDC}")

def remove_port_forwarding(port):
    print(f"\nSuppression du PONT sur le port {port}...")
    
    ps_script = f"""
    netsh interface portproxy delete v4tov4 listenport={port} listenaddress=0.0.0.0;
    Remove-NetFirewallRule -DisplayName "WSL Bridge Port {port}" -ErrorAction SilentlyContinue;
    Write-Host "Pont supprimé.";
    Pause;
    """
    
    ps_path = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    if not os.path.exists(ps_path):
        ps_path = "powershell.exe"

    cmd = [
        ps_path, 
        "-Command", 
        f"Start-Process powershell -Verb RunAs -ArgumentList '-NoExit', '-Command', '{ps_script}'"
    ]
    
    try:
        subprocess.call(cmd)
        print(f"{Colors.GREEN}Commande envoyée à Windows.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Erreur: {e}{Colors.ENDC}")

# --- New Features: Firewall & Mirrored Mode ---

def fix_windows_ping():
    """Autorise le Ping entrant (ICMP) sur Windows via netsh (plus robuste)."""
    print(f"\n{Colors.WARNING}Configuration du Pare-feu Windows pour autoriser le PING (ICMP)...{Colors.ENDC}")
    
    # Netsh command to allow ICMPv4 Echo Request (Type 8) on all profiles
    # 1. Delete old rule to avoid duplicates
    # 2. Add new rule
    batch_cmd = (
        'netsh advfirewall firewall delete rule name="WSL Allow Ping" & '
        'netsh advfirewall firewall add rule name="WSL Allow Ping" protocol=icmpv4:8,any dir=in action=allow profile=any'
    )
    
    ps_path = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    if not os.path.exists(ps_path):
        ps_path = "powershell.exe"

    # We still use PowerShell to elevate privileges easily with Start-Process
    cmd = [
        ps_path, 
        "-Command", 
        f"Start-Process cmd -Verb RunAs -ArgumentList '/c', '{batch_cmd} & pause'"
    ]
    
    try:
        subprocess.call(cmd)
        print(f"{Colors.GREEN}Commande envoyée ! Une fenêtre noire a dû s'ouvrir et se fermer.{Colors.ENDC}")
        print(f"{Colors.CYAN}Testez le ping maintenant.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Erreur: {e}{Colors.ENDC}")

def configure_mirrored_mode():
    """Configure .wslconfig pour le mode Mirrored (Windows 11)."""
    username = "blemeill" # Hardcoded based on analysis
    config_path = f"/mnt/c/Users/{username}/.wslconfig"
    
    print(f"\n{Colors.WARNING}ACTIVATION du Mode Mirrored (Windows 11 uniquement !){Colors.ENDC}")
    print(f"Cela va créer/écraser : {Colors.BLUE}{config_path}{Colors.ENDC}")
    
    content = """[wsl2]
networkingMode=mirrored
firewall=true
"""
    try:
        with open(config_path, "w") as f:
            f.write(content)
        print(f"{Colors.GREEN}Fichier .wslconfig mis à jour.{Colors.ENDC}")
        print(f"{Colors.FAIL}IMPORTANT : Vous devez redémarrer WSL pour appliquer les changements.{Colors.ENDC}")
        print(f"Ouvrez un terminal Windows (cmd/powershell) et tapez : {Colors.BOLD}wsl --shutdown{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Erreur d'écriture : {e}{Colors.ENDC}")

def restore_nat_mode():
    """Supprime .wslconfig pour revenir au mode NAT par défaut."""
    username = "blemeill"
    config_path = f"/mnt/c/Users/{username}/.wslconfig"
    
    print(f"\n{Colors.WARNING}RETOUR au Mode NAT (Défaut){Colors.ENDC}")
    
    if os.path.exists(config_path):
        try:
            os.remove(config_path)
            print(f"{Colors.GREEN}Fichier .wslconfig supprimé.{Colors.ENDC}")
            print(f"{Colors.FAIL}IMPORTANT : Redémarrez WSL (wsl --shutdown) pour appliquer.{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}Erreur lors de la suppression : {e}{Colors.ENDC}")
    else:
        print(f"{Colors.BLUE}Aucune configuration personnalisée trouvée (déjà en NAT ?).{Colors.ENDC}")


def main_menu():
    while True:
        clear_screen()
        print(f"{Colors.HEADER}=== GESTIONNAIRE RÉSEAU WSL & PONT WINDOWS ==={Colors.ENDC}")
        
        print("\nADRESSES IP (Linux/WSL) :")
        current_ips = get_current_ips()
        for i, ip in enumerate(current_ips):
            print(f" - {Colors.BLUE}{ip}{Colors.ENDC}")

        print("\n--- GESTION IP LOCALE (Linux) ---")
        print(f" {Colors.GREEN}A{Colors.ENDC}. Ajouter une IP virtuelle (ex: 192.168.5.20)")
        print(f" {Colors.WARNING}S{Colors.ENDC}. Supprimer une IP virtuelle")
        
        print("\n--- PONT / BRIDGE (Accès depuis l'Extérieur) ---")
        print(f" {Colors.CYAN}P{Colors.ENDC}. Créer un Pont (Port Forwarding) Windows -> WSL")
        print(f" {Colors.CYAN}D{Colors.ENDC}. Détruire un Pont existant")

        print("\n--- FIXES & VISIBILITÉ (Windows 11) ---")
        print(f" {Colors.WARNING}F{Colors.ENDC}. Fixer le PING Windows (Autoriser ICMP)")
        print(f" {Colors.WARNING}M{Colors.ENDC}. Activer 'Mirrored Mode' (Visibilité Totale)")
        print(f" {Colors.CYAN}N{Colors.ENDC}. Restaurer Mode NAT (Défaut)")
        
        print(f"\n {Colors.BOLD}Q{Colors.ENDC}. Quitter")
        
        choice = input("\nVotre choix : ").strip().upper()
        
        if choice == 'A':
            new_ip = input("Entrez l'IP à ajouter (ex: 192.168.5.20) : ").strip()
            if new_ip:
                add_ip(new_ip)
                input("\nAppuyez sur Entrée pour continuer...")
        
        elif choice == 'S':
            try:
                ip_to_del = input("Entrez l'IP à supprimer (avec masque, ex: 192.168.5.20/24) : ").strip()
                if ip_to_del:
                    managed_remove_ip(ip_to_del)
            except ValueError:
                pass
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == 'P':
            port = input("Quel PORT voulez-vous ouvrir (ex: 80, 8080) ? ").strip()
            if port.isdigit():
                add_port_forwarding(port)
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == 'D':
            port = input("Quel PORT voulez-vous fermer ? ").strip()
            if port.isdigit():
                remove_port_forwarding(port)
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == 'F':
            fix_windows_ping()
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == 'M':
            configure_mirrored_mode()
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == 'N':
            restore_nat_mode()
            input("\nAppuyez sur Entrée pour continuer...")
            
        elif choice == 'Q':
            print("Au revoir !")
            break

if __name__ == "__main__":
    main_menu()
