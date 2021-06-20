/*
Class to create the public and private eys to files
Based on https://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
*/

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class RSA {

    Key pub, priv;

    public static void main(String[] args) throws NoSuchAlgorithmException, GeneralSecurityException, IOException {
        RSA rsa = new RSA();
        rsa.createRSA();
    }

    void createRSA() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        // Creating KeyPair generator object
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // Initializing the key pair generator
        // 2048 recommended as a good level of security
        keyPairGen.initialize(2048);
        // Generating the pair of keys
        KeyPair pair = keyPairGen.generateKeyPair();
        pub = pair.getPublic();
        System.out.println(pub);
        priv = pair.getPrivate();

        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = fact.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec priv = fact.getKeySpec(pair.getPrivate(), RSAPrivateKeySpec.class);
        saveKey("publicEncryption.key", pub.getModulus(), pub.getPublicExponent()); // this will give public key file
        saveKey("privateEncryption.key", priv.getModulus(), priv.getPrivateExponent()); // this will give private key file
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