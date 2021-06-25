import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AES {

    // Generate session key
    public static SecretKey generateAESKey() throws Exception {

        System.out.println("Generating AES session key...");
        SecureRandom sr = new SecureRandom();
        byte b[] = new byte[20];
        sr.nextBytes(b);
        
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, sr);
        SecretKey key = kg.generateKey();
        System.out.println("Session key: "+keyString(key));
        return key;
    }

    // Encrypt using session key
    public static byte[] AESEncryption(byte[] input, SecretKey sk, IvParameterSpec IV) throws Exception {
        System.out.println("Encrypting using AES session key.");
        System.out.println("Session key: "+keyString(sk));
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        c.init(Cipher.ENCRYPT_MODE, sk, IV);
        return c.doFinal(input);
    }

    // IV
    public static IvParameterSpec createInitializationVector() {
        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Decrypt using session key
    public static byte[] AESDecryption(byte[] cipher_text, SecretKey sk, IvParameterSpec IV) throws Exception {
        System.out.println("Decrypting using AES session key.");
        System.out.println("Session key: "+keyString(sk));
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        c.init(Cipher.DECRYPT_MODE, sk, IV);
        byte[] result = c.doFinal(cipher_text);
        return result;
    }

    public static String keyString(SecretKey key)
    {
        String stringKey = Base64.getEncoder().encodeToString(key.getEncoded());
        return stringKey;
    }
}