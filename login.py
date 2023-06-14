import hashlib
import os

PASSWORDS_FILE = 'passwords.txt'

#store password
def store_password(username, password):
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)  # Hash the password
    with open(PASSWORDS_FILE, 'a') as file:
        file.write(f"{username}:{salt.hex()}:{hashed_password.hex()}\n")  # Write the username, salt, and hashed password to the file

# username checking in file
def username_exists(username):
    with open(PASSWORDS_FILE, 'r') as file:
        for line in file:
            stored_username, _, _ = line.strip().partition(':')
            if stored_username == username:
                return True
    return False

# checking hash
def check_password(username, password):
    with open(PASSWORDS_FILE, 'r') as file:
        for line in file:
            stored_username, stored_salt_hex, stored_password_hex = line.strip().split(':')
            if stored_username == username:
                stored_salt = bytes.fromhex(stored_salt_hex)  # Convert the stored salt from hex to bytes
                stored_password = bytes.fromhex(stored_password_hex)  # Convert the stored hashed password from hex to bytes
                hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), stored_salt, 100000)  # Hash the input password with the stored salt
                if hashed_password == stored_password:  #checking the hash
                    return True
    return False

def signup():
    username = input("Enter a username: ")
    if username_exists(username):
        print("Username already exists. Please choose a different username.")
        return
    password = input("Enter a password: ")
    store_password(username, password)
    print("Signup successful!")
    
def login():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    if check_password(username, password):
        print("Login successful!")
        return username
    else:
        print("Invalid username or password.")
        return None

while True:
    print("FSOCIETY")
    print("1. Signup")
    print("2. Login")
    print("3. Quit")
    choice = input("Enter your choice (1-3): ")

    if choice == "1":
        signup()
    elif choice == "2":
        logged_in_username = login()
        if logged_in_username:
            print(f"Welcome, \033[0;31m{logged_in_username}\033[0m")
            break
    elif choice == "3":
        break
    else:
        print("Invalid choice. Please try again.")
