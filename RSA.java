/*
    https://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
    We end up with two files: public.key, which is distributed with our clients.
    Meanwhile, private.key, is kept secret on our server.
*/

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class RSA {

    Key pub, priv;

    public static void main(String[] args) throws NoSuchAlgorithmException, GeneralSecurityException, IOException{			
			System.out.println("Creating RSA class");
			RSA rsa = new RSA();
			rsa.createRSA();	
		}

    void createRSA() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException  {
        // Creating KeyPair generator object
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // Initializing the key pair generator
        keyPairGen.initialize(2048);
        // Generating the pair of keys
        KeyPair pair = keyPairGen.generateKeyPair();
        pub = pair.getPublic();
        System.out.println(pub);
        priv = pair.getPrivate();

        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = fact.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec priv = fact.getKeySpec(pair.getPrivate(), RSAPrivateKeySpec.class);
        saveKey("public.key", pub.getModulus(), pub.getPublicExponent()); // this will give public key file
        saveKey("private.key", priv.getModulus(), priv.getPrivateExponent()); // this will give private key file
    }

    void saveKey(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        ObjectOutputStream ObjOut = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));

        try {
            ObjOut.writeObject(mod);
            ObjOut.writeObject(exp);
            System.out.println("Key File Created: " + fileName);
        } catch (Exception e) {
            throw new IOException(" Error while writing the key object", e);
        } finally {
            ObjOut.close();
        }
    }
}
