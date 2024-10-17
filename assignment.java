import java.security.*; // This package contains classes that provide the security framework, including classes for generating key pairs (KeyPairGenerator), cryptographic algorithms (MessageDigest, Signature), and keys (PublicKey, PrivateKey).
import java.security.spec.*;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.KeyAgreement; //Part of java crypto, that allows us to make operations related to secuirt //This package contains classes for encryption and decryption, including Cipher and KeyAgreement. The KeyAgreement class in particular is responsible for executing key agreement protocols like Diffie-Hellman.y

public class assignment {

    // Characters used for key generation
    private static final String KEY_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";



 public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException { // Generating public and private keys
     KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH"); //We are getting DH as instance because it stand for DiffieHellman algorithm 
     keyPairGen.initialize(2048); // Key size
     return keyPairGen.generateKeyPair();
    }


    public static byte[] performKeyAgreement(PrivateKey ownPrivateKey, PublicKey otherPublicKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");  //We are getting DH as instance because it stand for DiffieHellman algorithm
        keyAgree.init(ownPrivateKey); //Initalizing the privatekey for and telling the KeyAgree to get ready to perform come computing meathods 
        keyAgree.doPhase(otherPublicKey, true); //Here we are passing the other person's public key and but adding  "doPhase" we are telling the algorithm to both combines the private and public key and generate a sharedkey
        return keyAgree.generateSecret(); //Here we are generating the key and its beloning to the both parties 
    }

    public static String deriveKey(byte[] sharedSecret, int length) {
        // Use a MessageDigest to hash the shared secret
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-256"); //SHA-256 is a hashing function that perform 256 hashing value
            //MessageDigest is used to generate hashed, part of java secuirty library
            hash.update(sharedSecret); //preparing the sharedSecret to be hashed 
            byte[] digest = hash.digest();
            
            // Convert the digest to a string using the KEY_CHARACTERS
            StringBuilder key = new StringBuilder(length);
            for (int i = 0; i < length; i++) { 
                int index = Byte.toUnsignedInt(digest[i]) % KEY_CHARACTERS.length();
                key.append(KEY_CHARACTERS.charAt(index));
            }
            return key.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not found.");
        }
    }


    //We can use this if we do not want to use the diffiehellman method
    /*
    public static String generateKey(int plaintextLength) { //When we call this function from the main function, this function tells the caller how long the key should be
        SecureRandom random = new SecureRandom(); //Here i used SecureRandom instead of regular Random class because SecureRandom is more designed to be used in secuirty senstive projects 
        StringBuilder key = new StringBuilder(plaintextLength);//i used StringBulider class instead of regular String becuase in java when you want to add new characters, it will create a new object for it which is inefficient
        for (int i = 0; i < plaintextLength; i++) {
            int index = random.nextInt(KEY_CHARACTERS.length()); //Selecting a random index from the KEY_CHARACTERS variable
            key.append(KEY_CHARACTERS.charAt(index)); //Appending the character at the random index we got 
        }
        //10
        //l
        return key.toString(); 
    }
    */

    public static String encrypt(String plaintext, String key) {
        StringBuilder ciphertext = new StringBuilder(); //Again here i used StringBulider for efficiency 
        for (int i = 0; i < plaintext.length(); i++) { //Looping throw the length of the plaintext
            char p = plaintext.charAt(i); //Selecting a character from the plaintext //Here we are taking the ascii values
            char k = key.charAt(i); //Selecting a character from the key //Here we are taking the ascii values
            char cipherChar = (char) (p ^ k); //Performing XOR operation
            ciphertext.append(cipherChar); //apending the result to the ciphertext
        
        }
        return ciphertext.toString();
    }


    public static String decrypt(String ciphertext, String key) {
        StringBuilder decryptedText = new StringBuilder();
        for (int i = 0; i < ciphertext.length(); i++) { 
            char c = ciphertext.charAt(i);
            char k = key.charAt(i);
            char plainChar = (char) (c ^ k);
            decryptedText.append(plainChar);

            
        }
        return decryptedText.toString();
    }




    public static void main(String[] args) {
        try{
        // Define 10 plaintexts
        List<String> plaintexts = new ArrayList<>();
        plaintexts.add("YAHYA");
        plaintexts.add("AYDIN_UNIVERSITY");
        plaintexts.add("ISTANBUL");
        plaintexts.add("CLASSROOM");
        plaintexts.add("PROFESSOR_ILHAM");
        plaintexts.add("ELDEN_RING");
        plaintexts.add("CRASH_BANDICOOT");
        plaintexts.add("PLAYSTATION5");
        plaintexts.add("FREE_PALESTINE");
        plaintexts.add("FREE_SYRIA");

        // Lists to store keys, ciphertexts, and decrypted texts
        List<String> keys = new ArrayList<>();
        List<String> ciphertexts = new ArrayList<>();
        List<String> decryptedTexts = new ArrayList<>();

        System.out.println("Encryption Process...\n");


        for (int i = 0; i < plaintexts.size(); i++) {
                // Simulate Yahya generating his key pair
                KeyPair YahyaKp = generateDHKeyPair();
                // Simulate Suha generating Her key pair
                KeyPair SuhaKp = generateDHKeyPair();

                // Yahya and Suha exchange public keys
                PublicKey YahyaPubKey = YahyaKp.getPublic(); //Getting the public key 
                PublicKey SuhaPubKey = SuhaKp.getPublic(); //Getting the public key

                // Yahya generates the shared secret using his private key and Suha's public key
                byte[] yahyaSharedSecret = performKeyAgreement(YahyaKp.getPrivate(), SuhaPubKey);

                // Suha generates the shared secret using her private key and Yahya's public key
                byte[] suhaSharedSecret = performKeyAgreement(SuhaKp.getPrivate(), YahyaPubKey);

                // Verify that both shared secrets are the same
                if (!MessageDigest.isEqual(yahyaSharedSecret, suhaSharedSecret)) {
                    throw new RuntimeException("Shared secrets do not match!");
                }

                // Derive the key from the shared secret
                String key = deriveKey(yahyaSharedSecret, plaintexts.get(i).length()); //Here we can either use YahyaSharedSecret or SuhaSharedSecert to derive the key, it doesn't matter becuase they are the same.
                keys.add(key);

                // Encrypt the plaintext
                String ciphertext = encrypt(plaintexts.get(i), key);
                ciphertexts.add(ciphertext);

                System.out.println("Plaintext " + (i + 1) + ": " + plaintexts.get(i));
                System.out.println("Shared Key " + (i + 1) + ": " + key);
                System.out.println("Ciphertext " + (i + 1) + ": " + "We will not print the ciphertext becuase you can't read it");
                System.out.println();
            }


        


        //We can use this without the diffie hellmen and comment the uppercode 
        /*
        for (int i = 0; i < plaintexts.size(); i++) {
            String plaintext = plaintexts.get(i);
            String key = generateKey(plaintext.length());
            String ciphertext = encrypt(plaintext, key);

            keys.add(key);
            ciphertexts.add(ciphertext);

        }
        */
        System.out.println("\nDecryption Process...\n");
        // Decryption

        for (int i = 0; i < ciphertexts.size(); i++) {
                String ciphertext = ciphertexts.get(i);
                String key = keys.get(i);
                String decryptedText = decrypt(ciphertext, key);
                decryptedTexts.add(decryptedText);

                System.out.println("Ciphertext " + (i + 1) + ": " + "We will not print the ciphertext because you can't read it");
                System.out.println("Shared Key " + (i + 1) + ": " + key);
                System.out.println("Decrypted Text " + (i + 1) + ": " + decryptedText);
                System.out.println();
            }



            //We can use this if we don't want to use diffie hellmen
        /*
        for (int i = 0; i < ciphertexts.size(); i++) {
            String ciphertext = ciphertexts.get(i);
            String key = keys.get(i);
            String decryptedText = decrypt(ciphertext, key);
            decryptedTexts.add(decryptedText);

        }
        */


        // Discard keys by clearing the list
        keys.clear();

        // Validation
        System.out.println("\nValidation Results:\n");
        for (int i = 0; i < plaintexts.size(); i++) {
            String originalText = plaintexts.get(i);
            String decrypted = decryptedTexts.get(i);
            if (originalText.equals(decrypted)) {
                System.out.println("Plaintext " + (i + 1) + " matches Decrypted Text " + (i + 1) + ": Passed the test");
            } else {
                System.out.println("Plaintext " + (i + 1) + " does NOT match Decrypted Text " + (i + 1) + ": Failed the test");
            }
        }
    } catch (Exception e) {
            e.printStackTrace();
        }
        
    }
    
}
