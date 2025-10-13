try:
    from .impl import hash_passphrase

except ImportError:
    from .stub import hash_passphrase


__all__ = ["hash_passphrase"]
