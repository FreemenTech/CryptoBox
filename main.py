#!/usr/bin/env python3
"""
CryptoBox v2.0 — Entry point.

Usage:
    python main.py                          Show help
    python main.py menu                     Interactive menu
    python main.py encrypt password ...     CLI encrypt (password mode)
    python main.py encrypt aes ...          CLI encrypt (AES key mode)
    python main.py decrypt password ...     CLI decrypt (password mode)
    python main.py decrypt aes ...          CLI decrypt (AES key mode)
    python main.py version                  Show version
"""

from cli import app

if __name__ == "__main__":
    app()
