from Crypto.Cipher import Blowfish
import binascii
import hashlib

def decrypt_blowfish_to_hex(ciphertext_hex, key, iv_hex):
    # Convert hex strings to bytes
    ciphertext = binascii.unhexlify(ciphertext_hex)
    key_bytes = key.encode('utf-8')
    iv = binascii.unhexlify(iv_hex)
    
    # Create a Blowfish cipher object in CBC mode
    cipher = Blowfish.new(key_bytes, Blowfish.MODE_CBC, iv)
    
    # Decrypt the ciphertext
    decrypted_bytes = cipher.decrypt(ciphertext)
    
    # Convert decrypted bytes to a hexadecimal string
    decrypted_hex = binascii.hexlify(decrypted_bytes).decode('utf-8')
    
    return decrypted_hex


def xor_strings(s1, s2):
    # Ensure both strings are of the same length
    if len(s1) != len(s2):
        raise ValueError("Strings must be of the same length")

    # Convert strings to byte arrays
    b1 = binascii.unhexlify(s1)
    b2 = binascii.unhexlify(s2)

    # Perform XOR operation byte-by-byte
    result = bytes(a ^ b for a, b in zip(b1, b2))

    # Convert the result back to a hex string
    return binascii.hexlify(result).decode('utf-8')


def padding_oracle_attack(ciphertext_hex, key, iv_hex, number):
    # Split the IV hex string into a list of byte pairs
    split_list_iv = [iv_hex[i:i+2] for i in range(0, len(iv_hex), 2)]
    
    for x in range(1, number + 1):        
        # Decrypt the ciphertext using the current IV
        decrypt_bf = decrypt_blowfish_to_hex(ciphertext_hex, key, ''.join(split_list_iv))
        # Split the decrypted hex string into a list of byte pairs
        split_list_decrypt = [decrypt_bf[i:i+2] for i in range(0, len(decrypt_bf), 2)]

        # Get the specific byte from the IV and decrypted text
        position_iv = split_list_iv[-x]
        position_decrypt = split_list_decrypt[-x]

        # Convert the current number to a hexadecimal string
        number_hex = format(number, '02x')

        # XOR the IV byte with the decrypted byte and then with the current number
        xor_a = xor_strings(position_iv, position_decrypt)
        xor_b = xor_strings(xor_a, number_hex)
        
        # Update the IV with the manipulated value
        split_list_iv[-x] = xor_b

    # Print the manipulated IV and decrypted text
    print(' '.join(split_list_iv), ' -> ', ' '.join(split_list_decrypt))
    return split_list_iv, split_list_decrypt


# Example usage

# http://blowfish.online-domain-tools.com/ used same function (generateIV) from their page's Javascript
def generate_iv(key):
    # Hash the key using SHA-1
    sha1_hash = hashlib.sha1(key.encode()).digest()    
    # Use the first 8 bytes of the SHA-1 hash as the IV
    iv = sha1_hash[:8]    
    # Format IV in hex
    iv_hex = binascii.hexlify(iv).decode('utf-8')
    # iv_formatted = ' '.join(iv_hex[i:i+2] for i in range(0, len(iv_hex), 2))    
    return iv_hex

# variables
key = "very very secret key"
iv_hex = generate_iv(key)
ciphertext_hex = "fface9cc092edae6"

# Perform the padding oracle attack with different numbers
padding_oracle_attack(ciphertext_hex, key, iv_hex, 1)
padding_oracle_attack(ciphertext_hex, key, iv_hex, 2)
padding_oracle_attack(ciphertext_hex, key, iv_hex, 3)
padding_oracle_attack(ciphertext_hex, key, iv_hex, 4)
padding_oracle_attack(ciphertext_hex, key, iv_hex, 5)
padding_oracle_attack(ciphertext_hex, key, iv_hex, 6)
padding_oracle_attack(ciphertext_hex, key, iv_hex, 7)
padding_oracle_attack(ciphertext_hex, key, iv_hex, 8)