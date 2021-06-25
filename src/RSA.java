
import java.io.*;
import java.security.*;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.cert.X509CertificateHolder;

public class RSA {

    Key pub, priv;

    public static void main(String[] args)
            throws NoSuchPaddingException, NoSuchAlgorithmException, GeneralSecurityException, IOException {

        System.out.println("This is the RSA Encryption class. Run Bob then Alice to use this application.");
    }

    // Encrypt using Public Key
    public static byte[] encrypt(byte[] input, PublicKey publicKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("Encrypting using public key of receiver in RSA/ECB/PKCS1Padding mode...");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipher.update(input);
        byte[] cipherText = cipher.doFinal();
        return cipherText;

    }

    // Decrypt using Private Key
    public static byte[] decrypt(byte[] input, PrivateKey privateKey) throws IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
                System.out.println("Decrypting using private key of receiver in RSA/ECB/PKCS1Padding mode...");
        System.out.println("Not showing private key for security reasons.");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decipheredText = cipher.doFinal(input);
        return decipheredText;
    }

    // Authenticate using Public Key
    public static boolean authenticate(byte[] generated, byte[] received, PublicKey key) throws IOException,
            SignatureException, NoSuchAlgorithmException, InvalidKeyException, InterruptedException {
        System.out.println("Verifying signature using public key of sender...");
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(key);
        sign.update(generated);
        boolean bool = sign.verify(received);
        return bool;

    }

    // Sign using Private Key
    public static byte[] sign(byte[] input, PrivateKey key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        System.out.println("Signing using private key of sender (SHA-256 with RSA)...");
        System.out.println("Not showing private key for security reasons.");
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(key);
        sign.update(input);
        byte[] signature = sign.sign();
        return signature;
    }

    // Generate digest
    public static byte[] genDigest(X509CertificateHolder cert) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InterruptedException {
        System.out.println("Calculating digest using SHA-256...");
        byte[] input = cert.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(input);
        byte[] digest = md.digest();
        return digest;

    }

    public static String keyString(PublicKey key)
    {
        String stringKey = Base64.getEncoder().encodeToString(key.getEncoded());
        return stringKey;
    }

    public static KeyPair genKeys() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(2048, SecureRandom.getInstance("SHA1PRNG"));
        KeyPair keyPair = kpGen.generateKeyPair();
        return keyPair;
    }
}