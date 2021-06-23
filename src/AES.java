import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AES
{
    public static SecretKey generateAESKey() throws Exception {

        // Generate Secret Key
        SecureRandom sr = new SecureRandom();
        byte b[] = new byte[20];
        sr.nextBytes(b);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, sr);
        SecretKey key = kg.generateKey();
        return key;
    }

    public static byte[] AESEncryption(byte[] input, SecretKey sk, IvParameterSpec IV) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        c.init(Cipher.ENCRYPT_MODE, sk, IV);
        return c.doFinal(input);
    }

    public static IvParameterSpec createInitializationVector() {

        // Used with encryption
        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static byte[] AESDecryption(byte[] cipher_text, SecretKey sk, IvParameterSpec IV) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        c.init(Cipher.DECRYPT_MODE, sk, IV);
        byte[] result = c.doFinal(cipher_text);
        return result;
    }
}