try:
    from .impl import decrypt, encrypt

except ImportError:
    from .stub import decrypt, encrypt


__all__ = [
    "decrypt",
    "encrypt",
]
