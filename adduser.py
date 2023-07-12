import os
import getpass
import crypt
import subprocess
from datetime import datetime, timedelta

# Get user input
username = input("Enter the username: ")
password = getpass.getpass("Enter the password: ")
days = int(input("Enter the number of days until the account expires: "))
sshlimiter = int(input("Enter the connection limit for the SSH user account: "))

# Validate the inputs...

# Create a new user
encPassword = crypt.crypt(password,"22")
try:
    subprocess.run(['useradd', '-p', encPassword, '-e', (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d'), '-M', '-s', '/bin/false', username], check=True)
    print(f"User {username} has been added to system!")
except subprocess.CalledProcessError:
    print(f"Failed to add user {username} to system.")

# Add the new user to an SSH user database
with open("/root/users.db", "a") as file:
    file.write(f"{username} {sshlimiter}\n")

# If OpenVPN is installed on the system, ask the user if they want to generate an OpenVPN configuration file (.ovpn file) for this user.
# ... (this would require further system-specific commands that Python is not well-suited to perform)
