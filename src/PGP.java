
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PGP {
    static int hashLength;
    static int messageLength;
    static int IVLength;
    static int sessionKeyLength;
    static int AESLength;

    
    public static byte[] encrypt(byte[] message, PublicKey receiverKey, PrivateKey senderKey) throws Exception {

        System.out.println("Computing hash of message using sender private key.");
        byte[] hashSigned = RSA.sign(message, senderKey);
        byte[] hashAndMessage = new byte[hashSigned.length + message.length];
        hashLength = hashSigned.length;
        messageLength = message.length;

        System.out.println("Concatenating hash and message.");
        System.arraycopy(hashSigned, 0, hashAndMessage, 0, hashSigned.length);
        System.arraycopy(message, 0, hashAndMessage, hashSigned.length, message.length);
        
        //Compression goes here
         
        System.out.println("Generating one-time session key.");
         SecretKey sk = AES.generateAESKey();
         IvParameterSpec IV = AES.createInitializationVector();
         byte[] initializationVector = IV.getIV();
         IVLength = initializationVector.length;

        System.out.println("Encrypting payload with session key.");
        byte[] AESEncryption = AES.AESEncryption(hashAndMessage, sk, IV);
        AESLength = AESEncryption.length;

        System.out.println("Encrypting session key with receiver public key.");
        
         byte[] sessionKey = RSA.encrypt(sk.getEncoded(), receiverKey);
         sessionKeyLength = sessionKey.length;

         System.out.println("Concatenating encrypted session key with encrypted payload.");
         byte[] encryptedPayload = new byte[IVLength + AESEncryption.length + sessionKey.length];
         
         System.arraycopy(initializationVector, 0, encryptedPayload, 0, initializationVector.length);

         System.arraycopy(sessionKey, 0, encryptedPayload, initializationVector.length, sessionKey.length);
         System.arraycopy(AESEncryption, 0, encryptedPayload, initializationVector.length+sessionKey.length, AESEncryption.length);
    
        System.out.println("Sending message...");
        return encryptedPayload;
    }

    public static String decrypt(byte[] payload, PrivateKey receiverKey, PublicKey senderKey, int ivl, int skl, int aesl, int hl, int ml)
            throws Exception {
        
        System.out.println("Decrypting session key using receiver private key.");
        byte[] iv = Arrays.copyOfRange(payload, 0, ivl);
        IvParameterSpec IV  = new IvParameterSpec(iv);

        //Split payload into Session Key
        byte[] sk = Arrays.copyOfRange(payload, ivl, ivl+skl);
        byte[] skdecrypted = RSA.decrypt(sk, receiverKey);
        SecretKeySpec sessionKey = new SecretKeySpec(skdecrypted, "AES");

        //Split payload into hash and message
        byte[] AESsegment = Arrays.copyOfRange(payload, ivl+skl, payload.length);
        
        //Decompress goes here

        System.out.println("Decrypting payload body with session key.");
        byte[] AESdecrypted = AES.AESDecryption(AESsegment, sessionKey, IV);
        
        byte[] hashSigned = Arrays.copyOfRange(AESdecrypted, 0, hl);
        byte[] m = Arrays.copyOfRange(AESdecrypted, hl, ml+hl);

        String message = new String(m, StandardCharsets.UTF_8);

        System.out.println("Verifying received hash with generated hash using sender public key.");
        if (RSA.authenticate(m, hashSigned, senderKey))
        {
            return message;
        }
        else
        {
            return "Local hash did not match received hash.";
        }

    }

    public static int getHashLength() {
        return hashLength;
    }

    public static int getAESLength() {
        return AESLength;
    }

    public static int getMessageLength() {
        return messageLength;
    }

    public static int getIVLength()
    {
        return IVLength;
    }

    public static int getSessionKeyLength()
    {
        return sessionKeyLength;
    }

}