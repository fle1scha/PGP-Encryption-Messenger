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

    public static byte[] AESEncryption(String plain_text, SecretKey sk, byte[] IV) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
        c.init(Cipher.ENCRYPT_MODE, sk, ivParameterSpec);
        return c.doFinal((plain_text).getBytes());
    }

    public static byte[] createInitializationVector() {

        // Used with encryption
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    public static String AESDecryption(byte[] cipher_text, SecretKey sk, byte[] IV) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        c.init(Cipher.DECRYPT_MODE, sk, ivParameterSpec);
        byte[] result = c.doFinal(cipher_text);
        return new String(result);
    }
}