from tinyec import registry
import secrets

curve = registry.get_curve('secp192r1')

privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g
print("private key:", privKey)
print("public key:", pubKey)


with open('public_key_lec.pem', 'wb') as f:
    f.write(privKey)
