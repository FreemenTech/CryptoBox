"""
CryptoBox v2.0 — Typer CLI mode.

Scriptable command-line interface with subcommands:

    cryptobox encrypt password <input> <output>
    cryptobox encrypt aes <input> <output> --key-name <name>
    cryptobox decrypt password <input> <output>
    cryptobox decrypt aes <input> <output> --key-name <name>

Passwords are always prompted interactively (never passed as arguments,
which would leak into shell history and process listings).
"""

import sys
import typer
from typing import Annotated

from constants import __version__, MIN_PASSWORD_LENGTH
from crypto_engine import (
    encrypt_file_password,
    decrypt_file_password,
    encrypt_file_aes,
    decrypt_file_aes,
    generate_aes_key,
    decrypt_key_file,
)

# ── App hierarchy ──────────────────────────────────────────────
app = typer.Typer(
    name="cryptobox",
    help="CryptoBox — Secure file encryption tool.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

encrypt_app = typer.Typer(
    help="Encrypt files.",
    no_args_is_help=True,
)

decrypt_app = typer.Typer(
    help="Decrypt files.",
    no_args_is_help=True,
)

app.add_typer(encrypt_app, name="encrypt")
app.add_typer(decrypt_app, name="decrypt")


# ── Shared helpers ─────────────────────────────────────────────

def _prompt_password_encrypt() -> str:
    """Prompt for password with confirmation (hidden)."""
    password = typer.prompt("Password", hide_input=True)
    if len(password) < MIN_PASSWORD_LENGTH:
        typer.echo(
            f"Error: password too short "
            f"(minimum {MIN_PASSWORD_LENGTH} characters)",
            err=True,
        )
        raise typer.Exit(code=1)

    confirm = typer.prompt("Confirm password", hide_input=True)
    if password != confirm:
        typer.echo("Error: passwords do not match", err=True)
        raise typer.Exit(code=1)

    return password


def _prompt_password_decrypt() -> str:
    """Prompt for password (hidden, no confirmation)."""
    password = typer.prompt("Password", hide_input=True)
    if not password:
        typer.echo("Error: password required", err=True)
        raise typer.Exit(code=1)
    return password


def _success(message: str) -> None:
    typer.echo(f"✔ {message}")


def _fail(message: str) -> None:
    typer.echo(f"✖ {message}", err=True)
    raise typer.Exit(code=1)


# ══════════════════════════════════════════════════════════════
#                       ENCRYPT COMMANDS
# ══════════════════════════════════════════════════════════════

@encrypt_app.command("password")
def encrypt_password_cmd(
    input_file: Annotated[str, typer.Argument(help="File to encrypt")],
    output_file: Annotated[str, typer.Argument(help="Output encrypted file")],
) -> None:
    """Encrypt a file with a password (PBKDF2 + AES-256-GCM)."""
    try:
        password = _prompt_password_encrypt()
        encrypt_file_password(input_file, output_file, password)
        _success(f"Encrypted → {output_file}")
    except Exception as e:
        _fail(str(e))


@encrypt_app.command("aes")
def encrypt_aes_cmd(
    input_file: Annotated[str, typer.Argument(help="File to encrypt")],
    output_file: Annotated[str, typer.Argument(help="Output encrypted file")],
    key_name: Annotated[
        str,
        typer.Option("--key-name", "-k", help="Key file name (without .enc)"),
    ] = "cryptobox_key",
) -> None:
    """Encrypt a file with a random AES-256 key (key protected by password)."""
    try:
        password = _prompt_password_encrypt()
        aes_key = generate_aes_key(key_name, password)
        encrypt_file_aes(input_file, output_file, aes_key)
        _success(f"Encrypted → {output_file}")
        _success(f"Key saved → {key_name}.enc (keep this file safe)")
    except Exception as e:
        _fail(str(e))


# ══════════════════════════════════════════════════════════════
#                       DECRYPT COMMANDS
# ══════════════════════════════════════════════════════════════

@decrypt_app.command("password")
def decrypt_password_cmd(
    input_file: Annotated[str, typer.Argument(help="Encrypted file")],
    output_file: Annotated[str, typer.Argument(help="Output decrypted file")],
) -> None:
    """Decrypt a password-encrypted file."""
    try:
        password = _prompt_password_decrypt()
        decrypt_file_password(input_file, output_file, password)
        _success(f"Decrypted → {output_file}")
    except Exception as e:
        _fail(str(e))


@decrypt_app.command("aes")
def decrypt_aes_cmd(
    input_file: Annotated[str, typer.Argument(help="Encrypted file")],
    output_file: Annotated[str, typer.Argument(help="Output decrypted file")],
    key_name: Annotated[
        str,
        typer.Option("--key-name", "-k", help="Key file name (without .enc)"),
    ] = "cryptobox_key",
) -> None:
    """Decrypt a file using a password-protected AES key file."""
    try:
        key_file = f"{key_name}.enc"
        password = _prompt_password_decrypt()
        aes_key = decrypt_key_file(key_file, password)
        decrypt_file_aes(input_file, output_file, aes_key)
        _success(f"Decrypted → {output_file}")
    except Exception as e:
        _fail(str(e))


# ══════════════════════════════════════════════════════════════
#                       UTILITY COMMANDS
# ══════════════════════════════════════════════════════════════

@app.command("version")
def version_cmd() -> None:
    """Show CryptoBox version."""
    typer.echo(f"CryptoBox v{__version__}")


@app.command("menu")
def menu_cmd() -> None:
    """Launch interactive menu mode."""
    from interactive import run_interactive
    run_interactive()
