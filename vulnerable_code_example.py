import os

# Vulnerability 1: Hardcoded secret key (Insecure cryptographic key)
SECRET_KEY = "my_very_secret_key"

def insecure_code():
    # Vulnerability 2: Use of eval() (Potentially dangerous code execution)
    user_input = input("Enter some code to execute: ")
    eval(user_input)

def insecure_command():
    # Vulnerability 3: OS command injection
    command = "ls " + input("Enter a directory to list: ")
    os.system(command)

def main():
    insecure_code()
    insecure_command()

if __name__ == "__main__":
    main()
