import ctypes
import ctypes.wintypes
from hashlib import sha256

CRYPTPROTECTMEMORY_CROSS_PROCESS = ctypes.wintypes.DWORD(1)
CRYPTPROTECTMEMORY_BLOCK_SIZE = ctypes.wintypes.DWORD(16)

cleartext = b"Pageant"
s = (ctypes.c_char * 16)(*cleartext)


ctypes.windll.crypt32.CryptProtectMemory(s, CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_CROSS_PROCESS)
sha256_hash = sha256(b"\x00\x00\x00\x10" + s.value).hexdigest()
print(sha256_hash)
