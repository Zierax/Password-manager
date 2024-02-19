import random
import string
import os
import getpass
import bcrypt
import signal
from rich.console import Console
from rich.theme import Theme

# Define a custom theme for console output
custom_theme = Theme({
    "result_style": "bold green",
    "warningBbug": "bold yellow",
    "error_style": "bold red",
    "input_needed": "bold cyan",
    "info_style": "bold blue"
})

# Initialize Rich console with the custom theme
colored = Console(theme=custom_theme)

# Function to get the current directory
current_directory = os.getcwd()

# Define the folder where the passwords and users will be stored
DB_folder = os.path.join(current_directory, "password-manager", "DB")
PASSWORD_FILE = os.path.join(DB_folder, "passwords.txt")
USERS_FILE = os.path.join(DB_folder, "users.txt")

def generate_password(length=12, use_special_chars=True):
    """Generate a random password."""
    characters = string.ascii_letters + string.digits
    if use_special_chars:
        characters += string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def save_password(username, title, password):
    """Save the password to a file."""
    if not os.path.exists(DB_folder):
        os.makedirs(DB_folder)
    with open(PASSWORD_FILE, 'a') as f:
        f.write(f"{username}: {title}: {password}\n")

def retrieve_password(username, title):
    """Retrieve a password from the file."""
    with open(PASSWORD_FILE, 'r') as f:
        for line in f:
            if line.startswith(username) and line.split(": ")[1] == title:
                return line.split(": ")[2].strip()
    return None

def update_password(username, title, new_password):
    """Update a password in the file."""
    lines = []
    with open(PASSWORD_FILE, 'r') as f:
        for line in f:
            if line.startswith(username) and line.split(": ")[1] == title:
                line = f"{username}: {title}: {new_password}\n"
            lines.append(line)
    with open(PASSWORD_FILE, 'w') as f:
        f.writelines(lines)

def login():
    """Authenticate the user."""
    colored.print("[info_style]Login[/info_style]")
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    # Check if the user exists
    with open(USERS_FILE, 'r') as f:
        for line in f:
            if line.startswith(username):
                hashed_password = line.split(": ")[1].strip().encode('utf-8')
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    return username
    return None

def create_user():
    """Create a new user."""
    colored.print("[info_style]Create User[/info_style]")
    username = input("Enter a username: ")
    password = getpass.getpass("Enter a password: ")

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Save the user
    with open(USERS_FILE, 'a') as f:
        f.write(f"{username}: {hashed_password.decode('utf-8')}\n")

    colored.print("[result_style]User created successfully![/result_style]")

def main_menu(username):
    """Main menu of the password management system."""
    def ctrl_c_handler(signal, frame):
        colored.print("[error_style]Ctrl+C detected. Exiting...[/error_style]")
        exit(0)

    signal.signal(signal.SIGINT, ctrl_c_handler)

    while True:
        colored.print("[info_style]Password Management System[/info_style]")
        colored.print("1. Generate Password")
        colored.print("2. Save Password")
        colored.print("3. Retrieve Password")
        colored.print("4. Update Password")
        colored.print("5. Logout", style="bold yellow")
        colored.print("6. Exit", style="bold red")
        
        choice = input("Enter your choice: ")

        if choice == '1':
            length = int(input("Enter the length of the password: "))
            use_special_chars = input("Use special characters? (yes/no): ").lower() == 'yes'
            password = generate_password(length, use_special_chars)
            colored.print("[result_style]Generated Password:[/result_style] " + password, end="")

        elif choice == '2':
            title = input("Enter the title for the password: ")
            password = input("Enter the password: ")
            save_password(username, title, password)
            colored.print("[result_style]Password saved successfully![/result_style]")
        elif choice == '3':
            title = input("Enter the title for the password: ")
            password = retrieve_password(username, title)
            if password:
                colored.print(f"[result_style]Password for {title}:[/result_style] {password}")
            else:
                colored.print("[error_style]Password not found![/error_style]")
        elif choice == '4':
            title = input("Enter the title for the password: ")
            new_password = input("Enter the new password: ")
            update_password(username, title, new_password)
            colored.print("[result_style]Password updated successfully![/result_style]")
        elif choice == '5':
            colored.print("[info_style]Logged out successfully![/info_style]")
            return
        elif choice == '6':
            colored.print("[warningBbug]Exiting...[/warningBbug]")
            exit(0)
        else:
            colored.print("[error_style]Invalid choice. Please try again.[/error_style]")

if __name__ == "__main__":
    try:
        if not os.path.exists(DB_folder):
            os.makedirs(DB_folder)

        if not os.path.exists(PASSWORD_FILE):
            open(PASSWORD_FILE, 'w').close()

        if not os.path.exists(USERS_FILE):
            open(USERS_FILE, 'w').close()

        if os.path.getsize(USERS_FILE) == 0:
            create_user()

        username = login()
        if username:
            main_menu(username)
        else:
            colored.print("[error_style]Invalid username or password![/error_style]")
    except Exception as e:
        colored.print(f"[error_style]An error occurred: {str(e)}[/error_style]")
