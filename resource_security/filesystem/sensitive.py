from pathlib import Path


SENSITIVE_DIRECTORIES = {".ssh", ".aws", ".gnupg", ".config"}
SENSITIVE_SUFFIXES = {".pem", ".key"}
SENSITIVE_FILENAMES = {"credentials", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}


def is_sensitive_path(path: Path) -> bool:
    parts = {part.casefold() for part in path.parts}
    name = path.name.casefold()
    if parts & SENSITIVE_DIRECTORIES:
        return True
    if name == ".env" or name.startswith(".env."):
        return True
    if path.suffix.casefold() in SENSITIVE_SUFFIXES:
        return True
    if name in SENSITIVE_FILENAMES or name.startswith("credentials."):
        return True
    return False

