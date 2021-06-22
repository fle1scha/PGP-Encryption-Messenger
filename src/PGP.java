import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class PGP
{
    public byte[] encrypt(byte[] message, PublicKey receiverKey, PrivateKey senderKey) throws Exception
    {
        //Compute signed hash of message.
        byte[] hashSigned = RSA.sign(message, senderKey);
        byte[] hashAndMessage = new byte[hashSigned.length +  message.length];

        //Concatenate signed hash with message.
        System.arraycopy(hashSigned, 0, hashAndMessage, 0, hashSigned.length);
        System.arraycopy(message, 0, hashAndMessage, hashSigned.length, message.length);   
        
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
        System.arraycopy(AESEncryption, 0, encryptedPayload, sessionKey.length, AESEncryption.length);

        return encryptedPayload;

    }
}