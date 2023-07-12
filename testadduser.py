#!/usr/bin/env python3
import os
import shutil

# Function to generate client.ovpn
def newclient(username):
    shutil.copy("/etc/openvpn/client-common.txt", f"/root/{username}.ovpn")
    with open(f"/root/{username}.ovpn", "a") as ovpn_file:
        ovpn_file.write("<ca>\n")
        with open("/etc/openvpn/easy-rsa/pki/ca.crt") as ca_file:
            ovpn_file.write(ca_file.read())
        ovpn_file.write("</ca>\n")
        ovpn_file.write("<cert>\n")
        with open(f"/etc/openvpn/easy-rsa/pki/issued/{username}.crt") as cert_file:
            ovpn_file.write(cert_file.read())
        ovpn_file.write("</cert>\n")
        ovpn_file.write("<key>\n")
        with open(f"/etc/openvpn/easy-rsa/pki/private/{username}.key") as key_file:
            ovpn_file.write(key_file.read())
        ovpn_file.write("</key>\n")
        ovpn_file.write("<tls-auth>\n")
        with open("/etc/openvpn/ta.key") as ta_file:
            ovpn_file.write(ta_file.read())
        ovpn_file.write("</tls-auth>\n")

def fun_geraovpn(username, password):
    respost = input("Include username and password in the configuration file? (y/n): ")
    if respost.lower() == 'y':
        os.chdir("/etc/openvpn/easy-rsa/")
        os.system(f"./easyrsa build-client-full {username} nopass")
        newclient(username)
        with open(f"/root/{username}.ovpn") as ovpn_file:
            content = ovpn_file.read()
            content = content.replace("auth-user-pass", "<auth-user-pass>\n{}\n{}\n</auth-user-pass>".format(username, password))
            with open("/root/tmp.ovpn", "w") as tmp_file:
                tmp_file.write(content)
        shutil.move("/root/tmp.ovpn", f"/root/{username}.ovpn")
    else:
        os.chdir("/etc/openvpn/easy-rsa/")
        os.system(f"./easyrsa build-client-full {username} nopass")
        newclient(username)

# Get IP from /etc/IP
with open("/etc/IP") as ip_file:
    IP = ip_file.read()

cor1 = '\033[41;1;37m'
cor2 = '\033[44;1;37m'
scor = '\033[0m'

# Check if server.conf file exists
if os.path.exists("/etc/openvpn/server.conf"):
    with open("/etc/openvpn/server.conf") as server_conf_file:
        server_conf_lines = server_conf_file.readlines()
        for line in server_conf_lines:
            if line.startswith("port"):
                _Port = line.split()[1]
            elif "client-common.txt" in line:
                hst = server_conf_lines[7].split()[3]
                rmt = server_conf_lines[6]
                hedr = server_conf_lines[7]
                prxy = server_conf_lines[8]
                rmt2 = '/SSHPLUS?'
                rmt3 = 'www.vivo.com.br 8088'
                prx = '200.142.130.104'
                payload1 = '#payload "HTTP/1.0 [crlf]Host: m.youtube.com[crlf]CONNECT HTTP/1.0[crlf][crlf]|[crlf]"'
                payload2 = '#payload "CONNECT 127.0.0.1:1194[split][crlf] HTTP/1.0 [crlf][crlf]#"'
                vivo1 = "portalrecarga.vivo.com.br/recarga"
                vivo2 = "portalrecarga.vivo.com.br/controle/"
                vivo3 = "navegue.vivo.com.br/pre/"
                vivo4 = "navegue.vivo.com.br/controle/"
                vivo5 = "www.vivo.com.br"
                oi = "d1n212ccp6ldpw.cloudfront.net"
                bypass = "net_gateway"
                cert01 = "/etc/openvpn/client-common.txt"
                if hst == vivo1:
                    Host = "Portal Recharge"
                elif hst == vivo2:
                    Host = "Recharge Control"
                elif hst == vivo3:
                    Host = "Portal Browse"
                elif hst == vivo4:
                    Host = "Nav control"
                elif hst == f"{IP}:{_Port}":
                    Host = "Vivo MMS"
                elif hst == oi:
                    Host = "Oi"
                elif hst == bypass:
                    Host = "Bypass mode"
                elif hedr == payload1:
                    Host = "OPEN SOCKS"
                elif hedr == payload2:
                    Host = "OPEN SQUID"
                else:
                    Host = "Customized"

# Function to display a progress bar
def fun_bar(command1, command2):
    os.system(f"({command1}) >/dev/null 2>&1 &")
    os.system(f"({command2}) >/dev/null 2>&1 &")
    os.system("touch $HOME/fim")
    print("\033[1;33mWAIT \033[1;37m- \033[1;33m[", end='')
    while True:
        for i in range(18):
            print("\033[1;31m#", end='', flush=True)
            time.sleep(0.1)
        if os.path.exists("$HOME/fim"):
            os.remove("$HOME/fim")
            break
        print("\033[1;33m]")
        time.sleep(1)
        print("\033[1A\033[K\033[1;33mWAIT \033[1;37m- \033[1;33m[", end='')
    print("\033[1;33m]\033[1;37m -\033[1;32m OK !\033[1;37m")

def fun_edithost():
    print("\n\033[44;1;37m          CHANGE OVPN HOST            \033[0m")
    print("")
    print("\033[1;33mHOST IN USE\033[1;37m: \033[1;32m{}".format(Host))
    print("")
    print("\033[1;31m[\033[1;36m1\033[1;31m] \033[1;33mLIVE RECHARGE")
    print("\033[1;31m[\033[1;36m2\033[1;31m] \033[1;33mLIVE NAVIGATOR")
    print("\033[1;31m[\033[1;36m3\033[1;31m] \033[1;33mOPEN SOCKS \033[1;31m[\033[1;32mAPP MOD\033[1;31m]")
    print("\033[1;31m[\033[1;36m4\033[1;31m] \033[1;33mOPEN SQUID \033[1;31m[\033[1;32mPAYLOAD MODE\033[1;31m]")
    print("\033[1;31m[\033[1;36m5\033[1;31m] \033[1;33mBYPASS MODE \033[1;31m[\033[1;32mNO OVPN\033[1;31m]")
    print("\033[1;31m[\033[1;36m6\033[1;31m] \033[1;33mCUSTOMIZE")
    print("")
    print("\033[1;31m[\033[1;36m0\033[1;31m] \033[1;33mBACK")
    print("")
    while True:
        try:
            option = int(input("\033[1;37mOPTION: "))
            if option in range(0, 7):
                break
        except ValueError:
            pass
        print("\033[1;37mOPTION INVALID!")
    if option == 1:
        novoip = input("\n\033[1;37mIP / HOST: \033[1;32m")
        hst = vivo1
        rmt = "remote " + f"{novoip} {_Port}"
        rmt2 = '/SSHPLUS?'
        rmt3 = 'www.vivo.com.br 8088'
        prx = '200.142.130.104'
        payload1 = '#payload "HTTP/1.0 [crlf]Host: m.youtube.com[crlf]CONNECT HTTP/1.0[crlf][crlf]|[crlf]"'
        payload2 = '#payload "CONNECT 127.0.0.1:1194[split][crlf] HTTP/1.0 [crlf][crlf]#"'
    elif option == 2:
        novoip = input("\n\033[1;37mIP / HOST: \033[1;32m")
        hst = vivo3
        rmt = "remote " + f"{novoip} {_Port}"
        rmt2 = '/SSHPLUS?'
        rmt3 = 'www.vivo.com.br 8088'
        prx = '200.142.130.104'
        payload1 = '#payload "HTTP/1.0 [crlf]Host: m.youtube.com[crlf]CONNECT HTTP/1.0[crlf][crlf]|[crlf]"'
        payload2 = '#payload "CONNECT 127.0.0.1:1194[split][crlf] HTTP/1.0 [crlf][crlf]#"'
    elif option == 3:
        novoip = "gproxy.openvpn.net"
        hst = 'm.youtube.com'
        rmt = 'remote-random'
        prxy = '0.0.0.0 0'
        payload1 = '#payload "HTTP/1.0 [crlf]Host: m.youtube.com[crlf]CONNECT HTTP/1.0[crlf][crlf]|[crlf]"'
        payload2 = '#payload "CONNECT 127.0.0.1:1194[split][crlf] HTTP/1.0 [crlf][crlf]#"'
    elif option == 4:
        novoip = "127.0.0.1"
        hst = 'squidproxy.org'
        rmt = 'remote-random'
        prxy = '0.0.0.0 0'
        payload1 = '#payload "CONNECT 127.0.0.1:1194[split][crlf] HTTP/1.0 [crlf][crlf]#"'
        payload2 = '#payload "CONNECT 127.0.0.1:1194 HTTP/1.0[crlf][crlf]#"'
    elif option == 5:
        hst = bypass
        rmt = 'remote-random'
        prxy = '0.0.0.0 0'
        payload1 = '#payload "HTTP/1.0 [crlf]Host: m.youtube.com[crlf]CONNECT HTTP/1.0[crlf][crlf]|[crlf]"'
        payload2 = '#payload "CONNECT 127.0.0.1:1194[split][crlf] HTTP/1.0 [crlf][crlf]#"'
    elif option == 6:
        novoip = input("\n\033[1;37mIP / HOST: \033[1;32m")
        hst = novoip
        rmt = "remote " + f"{novoip} {_Port}"
        rmt2 = '/SSHPLUS?'
        rmt3 = 'www.vivo.com.br 8088'
        prx = '200.142.130.104'
        payload1 = '#payload "HTTP/1.0 [crlf]Host: m.youtube.com[crlf]CONNECT HTTP/1.0[crlf][crlf]|[crlf]"'
        payload2 = '#payload "CONNECT 127.0.0.1:1194[split][crlf] HTTP/1.0 [crlf][crlf]#"'
    elif option == 0:
        return
    else:
        return
    print("")
    if option != 0:
        print("\033[1;32mCHANGE MADE SUCCESSFULLY!")
        time.sleep(2)
    print("")
    fun_edithost()

def valid_ipv4_address(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) < 256 for part in parts)
    except ValueError:
        return False

# Get user input
username = input("Enter the username for the new account: ")
password = input("Enter the password for the new account: ")
days = input("Enter the number of days until the account expires: ")
limit = input("Enter the maximum number of connections for the account: ")

# Validate user input
if len(username) < 4 or len(username) > 32:
    print("Invalid username. The username must be between 4 and 32 characters.")
    exit(1)
if not valid_ipv4_address(IP):
    print("Invalid IP address. Please check the /etc/IP file.")
    exit(1)

# Check if username already exists
if os.path.exists(f"/etc/SSHPlus/senha/{username}"):
    print(f"Username '{username}' already exists. Please choose a different username.")
    exit(1)

# Create the user account
os.system(f"useradd {username}")
os.system(f"echo {username}:{password} | chpasswd")
os.system(f"chage -E $(date -d '+{days} days' '+%Y-%m-%d') {username}")

# Generate OpenVPN configuration file
if os.path.exists("/etc/openvpn/server.conf"):
    response = input("Generate OpenVPN configuration file? (y/n): ")
    if response.lower() == 'y':
        fun_geraovpn(username, password)

print("Account created successfully.")
