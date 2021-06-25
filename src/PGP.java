import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PGP {
    static int hashLength;
    static int messageLength;
    static int IVLength;
    static int sessionKeyLength;
    static int AESLength;

    public static int getHashLength() {
        return hashLength;
    }

    public static int getAESLength() {
        return AESLength;
    }

    public static int getMessageLength() {
        return messageLength;
    }

    public static int getIVLength() {
        return IVLength;
    }

    public static int getSessionKeyLength() {
        return sessionKeyLength;
    }

    // PGP Encryption Pipeline
    public static byte[] encrypt(byte[] message, PublicKey receiverKey, PrivateKey senderKey) throws Exception {
        // Compute signed hash of message.
        byte[] hashSigned = RSA.sign(message, senderKey);
        byte[] hashAndMessage = new byte[hashSigned.length + message.length];
        hashLength = hashSigned.length;
        messageLength = message.length;

        System.out.println("Concatenating hash with original message.");
        System.arraycopy(hashSigned, 0, hashAndMessage, 0, hashSigned.length);
        System.arraycopy(message, 0, hashAndMessage, hashSigned.length, message.length);

        // Compress payload
        hashAndMessage = compressBytes(hashAndMessage);

        SecretKey sk = AES.generateAESKey();
        IvParameterSpec IV = AES.createInitializationVector();
        byte[] initializationVector = IV.getIV();
        IVLength = initializationVector.length;

        byte[] AESEncryption = AES.AESEncryption(hashAndMessage, sk, IV);
        AESLength = AESEncryption.length;

        System.out.println("Encrypting session key with public key of receiver.");
        byte[] sessionKey = RSA.encrypt(sk.getEncoded(), receiverKey);
        sessionKeyLength = sessionKey.length;

        System.out.println("Concatenating encrypted session key with message payload.");
        byte[] encryptedPayload = new byte[IVLength + AESEncryption.length + sessionKey.length];

        System.arraycopy(initializationVector, 0, encryptedPayload, 0, initializationVector.length);

        System.arraycopy(sessionKey, 0, encryptedPayload, initializationVector.length, sessionKey.length);
        System.arraycopy(AESEncryption, 0, encryptedPayload, initializationVector.length + sessionKey.length,
                AESEncryption.length);

        System.out.println("Encrypted message: "+BytestoString(encryptedPayload));
        return encryptedPayload;
    }

    // PGP Decryption Pipeline
    public static byte[] decrypt(byte[] payload, PrivateKey receiverKey, PublicKey senderKey, int ivl, int skl,
            int aesl, int hl, int ml) throws Exception {

        // Split payload into IV
        byte[] iv = Arrays.copyOfRange(payload, 0, ivl);
        IvParameterSpec IV = new IvParameterSpec(iv);
        // Split payload into Session Key
        System.out.println("Decrypting session key.");
        byte[] sk = Arrays.copyOfRange(payload, 16, 272);
        byte[] skdecrypted = RSA.decrypt(sk, receiverKey);

        SecretKeySpec sessionKey = new SecretKeySpec(skdecrypted, "AES");

        // Split payload into hash and message
        byte[] AESsegment = Arrays.copyOfRange(payload, ivl + skl, payload.length);
        
        System.out.println("Decrypting message payload using session key.");
        byte[] AESdecrypted = AES.AESDecryption(AESsegment, sessionKey, IV);

        AESdecrypted = decompressBytes(AESdecrypted);
        
        System.out.println("Splitting hash and message.");
        byte[] hashSigned = Arrays.copyOfRange(AESdecrypted, 0, hl);
        byte[] m = Arrays.copyOfRange(AESdecrypted, hl, ml + hl);

        // Authenticate using public key.
        if (RSA.authenticate(m, hashSigned, senderKey)) {
            System.out.println("Calculated hash matches received hash.");
            System.out.println("Successfully decrypted");
            return m;
        } else {
            
            System.out.println("CONNECTION NOT SAFE. HASHES DO NOT MATCH. EXITING NOW.");
            System.exit(0);
            return m;
        }

    }

    // Compress using java.util.zip
    public static byte[] compressBytes(byte[] in) {

        System.out.println("Compressing...");
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            DeflaterOutputStream defl = new DeflaterOutputStream(out);
            defl.write(in);
            defl.flush();
            defl.close();

            return out.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(100);
            return null;
        }
    }

    // Decompress using java.util.zip
    public static byte[] decompressBytes(byte[] in) {

        System.out.println("Decompressing...");
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            InflaterOutputStream infl = new InflaterOutputStream(out);
            infl.write(in);
            infl.flush();
            infl.close();

            return out.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(101);
            return null;
        }
    }

    public static String BytestoString(byte[] input)
    {
        String stringKey = Base64.getEncoder().encodeToString(input);
        return stringKey;
    }
}