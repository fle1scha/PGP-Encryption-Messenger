
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {

    Key pub, priv;

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, GeneralSecurityException, IOException {
        
        //Instantiate the RSA algorithm for asymmetric encryption. 
        RSA rsa = new RSA();
        rsa.createRSA();
    }

    public void createRSA() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Creating KeyPair generator object
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // Initializing the key pair generator
        // 2048 recommended as a good level of security
        keyPairGen.initialize(2048);
        // Generating the pair of keys
        KeyPair pair = keyPairGen.generateKeyPair();
        pub = pair.getPublic();
        System.out.println("\n -- PUBLIC_KEY: \n" + pub + "\n");
        priv = pair.getPrivate();
        System.out.println(" -- PRIVATE_KEY: \n" + priv + "\n");

        /*KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = fact.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = fact.getKeySpec(pair.getPrivate(), RSAPrivateKeySpec.class);


        saveKey("publicEncryption.key", publicKeySpec.getModulus(), publicKeySpec.getPublicExponent()); // this will give public key file
        saveKey("privateEncryption.key", privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent()); // this will give private key file*/


        String secretMessage = "Shhhh - Don't tell anyone the secret message!";

        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, pub);


        // Encrypting a message
        byte[] secretMessageBytes = secretMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, priv);

        // Decrypting a message
        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

        System.out.println("Encrypted message: "+ encryptedMessageBytes);
        System.out.println("Decrypted message: "+ decryptedMessage);

    }

    void saveKey(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        ObjectOutputStream ObjOut = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));

        try {
            ObjOut.writeObject(mod);
            ObjOut.writeObject(exp);
            System.out.println("Key File Created: " + fileName);
        } catch (Exception e) {
            throw new IOException("Key could not be created", e);
        } finally {
            ObjOut.close();
        }
    }
}