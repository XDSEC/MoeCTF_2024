from hashlib import sha256
from secret import flag, secrets

assert flag == b'moectf{' + secrets + b'}'
assert secrets[:4] == b'2100' and len(secrets) == 10
hash_value = sha256(secrets).hexdigest()
print(f"{hash_value = }")
# hash_value = '3a5137149f705e4da1bf6742e62c018e3f7a1784ceebcb0030656a2b42f50b6a'
