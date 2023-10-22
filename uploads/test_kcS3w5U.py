# Import the Pyfhel library
import Pyfhel

# Create a new Pyfhel context
HE = Pyfhel()
HE.contextGen(p=65537, m=4096, flagBatching=True)

# Encode the word "admin" as bytes
plaintext = b"admin"

# Encrypt the bytes using PHE
ciphertext = HE.encryptBinary(plaintext)

# Print the encrypted result
print(f"The encrypted result of 'admin' is: {ciphertext}")
#hello