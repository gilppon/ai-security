from pathlib import Path
import re


WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def validate_path_input(path: str) -> None:
    if "\x00" in path or path != path.strip():
        raise ValueError("path contains invalid characters")
    normalized = path.replace("/", "\\")
    if normalized.startswith("\\\\"):
        raise ValueError("UNC and device paths are not authorized")
    without_drive = normalized[2:] if re.match(r"^[A-Za-z]:", normalized) else normalized
    if ":" in without_drive:
        raise ValueError("alternate data streams are not authorized")
    for part in (item for item in normalized.split("\\") if item not in {"", ".", ".."}):
        base_name = part.split(".", 1)[0].upper()
        if base_name in WINDOWS_RESERVED_NAMES:
            raise ValueError("reserved device path is not authorized")


def resolve_candidate(path: str, base_root: Path | None) -> Path:
    validate_path_input(path)
    candidate = Path(path)
    if not candidate.is_absolute():
        if base_root is None:
            raise ValueError("relative path requires an allowed root")
        candidate = base_root / candidate
    return candidate.resolve(strict=False)


def containing_root(candidate: Path, roots: tuple[Path, ...]) -> Path | None:
    matches = [root for root in roots if candidate == root or candidate.is_relative_to(root)]
    if not matches:
        return None
    return max(matches, key=lambda item: len(item.parts))
