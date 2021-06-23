import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.SecretKey;

public class PGP
{
    static int hashLength;
    static int messageLength;

    public static int getHashLength()
    {
        return hashLength;
    }
    public static int getMessageLength()
    {
        return messageLength;
    }
    public static byte[] encrypt(byte[] message, PublicKey receiverKey, PrivateKey senderKey) throws Exception
    {
        //Compute signed hash of message.
        byte[] hashSigned = RSA.sign(message, senderKey);
        byte[] hashAndMessage = new byte[hashSigned.length +  message.length];
        hashLength = hashSigned.length;
        messageLength = message.length;

        //Concatenate signed hash with message.
        System.arraycopy(hashSigned, 0, hashAndMessage, 0, hashSigned.length);
        System.arraycopy(message, 0, hashAndMessage, hashSigned.length, message.length);   
        /*
        //Compression goes here

        //Encrypt message with session key.
        SecretKey sk = AES.generateAESKey();
        byte[] IV = AES.createInitializationVector();
        byte[] AESEncryption = AES.AESEncryption(hashAndMessage, sk, IV);

        //Encrypt session key with receivers public key.
        byte[] sessionKey = RSA.encrypt(sk.getEncoded(), receiverKey);

        //Concatenate session key payload with encrypted message and hash.
        byte[] encryptedPayload = new byte[AESEncryption.length + sessionKey.length];
        System.arraycopy(sessionKey, 0, encryptedPayload, 0, sessionKey.length);
        System.arraycopy(AESEncryption, 0, encryptedPayload, sessionKey.length, AESEncryption.length);*/

        return hashAndMessage;
    }

    public static String decrypt(byte[] payload, PrivateKey receiverKey, PublicKey senderKey, int hl, int ml) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException, InterruptedException
    {
        byte[] hashSigned = Arrays.copyOfRange(payload, 0, hl);
        byte[] m = Arrays.copyOfRange(payload, hl, hl+ml);

        String message = new String(m, StandardCharsets.UTF_8);
        return message+" "+RSA.authenticate(m, hashSigned, senderKey);

    }
}