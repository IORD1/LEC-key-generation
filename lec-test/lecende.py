from tinyec import registry
from tinyec.ec import Curve,SubGroup
from Crypto.Cipher import AES
import hashlib, secrets, binascii

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP160r1')
# p1707 secp192r1
print(curve)

def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

print('-----------------------------INPUT TEXT-----------------------------------')
msg = b'Text to be encrypted by ECC public key and ' \
      b'decrypted by its corresponding ECC private key'
print("original msg:", msg)

print('-----------------------------PRIVATE KEY-----------------------------------')

# privKey = 68794872482351044252047421765157889268548094239707126235078295118592505405678
privKey = 8208938760820893876038760820893876082089387608208938760387608208
# privKey = 82089387605446868468684656868688686868
# privKey = secrets.randbelow(curve.field.n)
print(privKey)


# with open('public_key_lec.pem', 'wb') as f:
#     f.write(privKey)


print('------------------------------PUBLIC KEY----------------------------------')
pubKey = privKey * curve.g
print(pubKey)
# with open('private_key_lec.pem', 'wb') as f:
#     f.write(pubKey)


encryptedMsg = encrypt_ECC(msg, pubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0])
}
print('------------------------------ENCRYPTING----------------------------------')
print("encrypted msg:", encryptedMsgObj)
print('------------------------------DECRYPTING----------------------------------')

decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
print("decrypted msg:", decryptedMsg)
print('------------------------------END----------------------------------')


















# from tinyec import registry
# from Crypto.Cipher import AES
# import hashlib, secrets, binascii

# def encrypt_AES_GCM(msg, secretKey):
#     aesCipher = AES.new(secretKey, AES.MODE_GCM)
#     ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
#     return (ciphertext, aesCipher.nonce, authTag)

# def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
#     aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
#     plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
#     return plaintext

# def ecc_point_to_256_bit_key(point):
#     sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
#     sha.update(int.to_bytes(point.y, 32, 'big'))
#     return sha.digest()

# curve = registry.get_curve('brainpoolP256r1')

# def encrypt_ECC(msg, pubKey):
#     ciphertextPrivKey = secrets.randbelow(curve.field.n)
#     sharedECCKey = ciphertextPrivKey * pubKey
#     secretKey = ecc_point_to_256_bit_key(sharedECCKey)
#     ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
#     ciphertextPubKey = ciphertextPrivKey * curve.g
#     return (ciphertext, nonce, authTag, ciphertextPubKey)

# def decrypt_ECC(encryptedMsg, privKey):
#     (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
#     sharedECCKey = privKey * ciphertextPubKey
#     secretKey = ecc_point_to_256_bit_key(sharedECCKey)
#     plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
#     return plaintext

# msg = b'Text to be encrypted by ECC public key and ' \
#       b'decrypted by its corresponding ECC private key'
# print("original msg:", msg)
# # privKey = secrets.randbelow(curve.field.n)
# # privKey = 68794872482351044252047421765157889268548094239707126235078295118592505405671
# privKey = 12445796548756985214563256985479552154578551125587474555122545458784565842525
# pubKey = privKey * curve.g
# print('------------------------------')
# print(curve.field.n)
# print('------------------------------')
# print(pubKey)
# print('------------------------------')


# encryptedMsg = encrypt_ECC(msg, pubKey)
# encryptedMsgObj = {
#     'ciphertext': binascii.hexlify(encryptedMsg[0]),
#     'nonce': binascii.hexlify(encryptedMsg[1]),
#     'authTag': binascii.hexlify(encryptedMsg[2]),
#     'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
# }
# print("encrypted msg:", encryptedMsgObj)

# decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
# print("decrypted msg:", decryptedMsg)