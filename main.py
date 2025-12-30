from generate_key import generate_aes_key
from encrypt_decrypt import decrypt_file, encrypt_file
from password_encryption import (
    encrypt_file_password,
    decrypt_file_password,
    decrypt_key_file
)
import os
from rich import print
from rich.panel import Panel


#======================================================
#                    UTILS
#======================================================

def file_exists(path: str) -> bool:
    return os.path.isfile(path)


def file_not_exists(path: str) -> bool:
    return not os.path.exists(path)


def valid_filename(name: str) -> bool:
    forbidden = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    return bool(name) and not any(c in name for c in forbidden)


def ask_existing_file(prompt: str) -> str:
    path = input(prompt).strip()
    if not file_exists(path):
        raise FileNotFoundError("File does not exist")
    return path


def ask_new_file(prompt: str) -> str:
    name = input(prompt).strip()
    if not valid_filename(name):
        raise ValueError("Invalid file name")
    if not file_not_exists(name):
        raise FileExistsError("File already exists")
    return name


#======================================================
#                       MENU
#======================================================

print(Panel("[bold cyan]CRYPTOBOX CLI[/bold cyan]\nSecure file encryption tool", expand=False))

while True:
    print(Panel(
        "[bold]Main Menu[/bold]\n"
        "1- Encrypt file\n"
        "2- Decrypt file\n"
        "3- Exit",
        expand=False
    ))

    choix = input("> ").strip()

    #===================================== ENCRYPT FILE ============================================
    if choix == "1":
        while True:
            print(Panel(
                "[bold]Encryption Menu[/bold]\n"
                "1- Default encryption with password\n"
                "2- Encryption with AES + protected key file (password)\n"
                "0- Return",
                expand=False
            ))

            choix = input("> ").strip()

            #------------------ 1- Default encryption with password ------------------
            if choix == "1":
                try:
                    input_file = ask_existing_file("Put file path : ")
                    output_file = ask_new_file("Put output encrypted file name : ")
                    password = input("Put strong password : ").strip()

                    if not password:
                        raise ValueError("Password required")

                    encrypt_file_password(input_file, output_file, password)
                    print("[green]✔ Encryption completed successfully[/green]")
                    break

                except Exception as e:
                    print(f"[red]✖ Error:[/red] {e}")

            #------------------ 2- AES + protect key file with password ------------------
            elif choix == "2":
                try:
                    input_file = ask_existing_file("Put file path : ")
                    output_file = ask_new_file("Put output encrypted file name : ")
                    key_name = input("Put AES key file name (without extension) : ").strip()
                    password = input("Put strong password to protect key file : ").strip()

                    if not valid_filename(key_name):
                        raise ValueError("Invalid key file name")
                    if not password:
                        raise ValueError("Password required")

                    aes_key = generate_aes_key(key_name, password)
                    encrypt_file(input_file, output_file, aes_key)

                    print("[green]✔ Encryption completed successfully[/green]")
                    break

                except Exception as e:
                    print(f"[red]✖ Error:[/red] {e}")


            elif choix == "0":
                break
            else:
                print("[red]Wrong choice[/red]")

    #==================================== DECRYPT FILE ================================================
    elif choix == "2":
        while True:
            print(Panel(
                "[bold]Decryption Menu[/bold]\n"
                "1- Default decryption with password\n"
                "2- Decryption with AES + protected key file (password)\n"
                "0- Return",
                expand=False
            ))

            choix = input("> ").strip()

            #------------------ 1- Default decryption with password ------------------
            if choix == "1":
                try:
                    input_file = ask_existing_file("Put file path : ")
                    output_file = ask_new_file("Put output file name : ")
                    password = input("Put your password : ").strip()

                    if not password:
                        raise ValueError("Password required")

                    decrypt_file_password(input_file, output_file, password)
                    print("[green]✔ Decryption completed successfully[/green]")
                    break

                except Exception as e:
                    print(f"[red]✖ Error:[/red] {e}")

            #------------------ 2- AES + protected key file with password ------------------
            elif choix == "2":
                try:
                    input_file = ask_existing_file("Put file path : ")
                    output_file = ask_new_file("Put output file name : ")
                    key_name = input("Put AES key file name (without .enc) : ").strip()
                    password = input("Put password to decrypt key file : ").strip()

                    if not valid_filename(key_name):
                        raise ValueError("Invalid key file name")
                    if not password:
                        raise ValueError("Password required")

                    key_file = f"{key_name}.enc"
                    if not file_exists(key_file):
                        raise FileNotFoundError("Key file not found")

                    aes_key = decrypt_key_file(key_file, password)
                    decrypt_file(input_file, output_file, aes_key)

                    print("[green]✔ Decryption completed successfully[/green]")
                    break

                except Exception as e:
                    print(f"[red]✖ Error:[/red] {e}")

            elif choix == "0":
                break
            else:
                print("[red]Wrong choice[/red]")

    #======================== EXIT PROGRAM =========================
    elif choix == "3":
        print("[cyan]Good Bye 👋[/cyan]")
        break

    else:
        print("[red]Choose a correct number[/red]")
