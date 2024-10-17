This code simulates the Diffie-Hellman key exchange algorithm to encrypt and decrypt plaintext messages. It demonstrates how two parties, Yahya and Suha, can securely generate and exchange keys to establish a shared secret.

Both Yahya and Suha generate their own key pairs and exchange public keys. Using their private keys and the other party's public key, they derive a shared secret. This shared secret is then hashed and used to create a key for encryption.

The program encrypts a set of plaintext messages using an XOR-based encryption method and then decrypts them using the same shared key. It ensures that the decrypted text matches the original plaintext.

This process shows how two parties can securely communicate without directly sharing the encryption key.
