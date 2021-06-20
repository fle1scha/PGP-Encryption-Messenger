// NIS 2021
// Bob (Server) Class that sends and receives data

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.security.spec.RSAPrivateKeySpec;
import javax.crypto.*;
import java.math.BigInteger;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Bob {
    static boolean exit = false;
    static String IV = "placeholder";
    int i, portNumber;
    private Cipher keyDecipher;
    SecretKey AESKey;
    private Cipher ServerDecryptCipher;
    private Cipher ServerEncryptCipher;
    private message m;
    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;
    message messageToSend;

    // Bob is acting as the server and will have a port number he opens for
    // connection from Alice the client
    public Bob(int portNumber) {
        this.portNumber = portNumber;
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        int portNumber = 8002;
        Bob server = new Bob(portNumber);
        server.startBob();
    }

    void startBob() throws IOException {
        ServerSocket serverSocket = new ServerSocket(portNumber);
        System.out.println("Bob has started his day.\nWaiting for Alice to call...");
        Socket socket = serverSocket.accept(); // accepting the connection.
        System.out.println("Connection established at " + socket);
        alice t = new alice(socket);
        t.run();
        serverSocket.close();
    }

    class alice extends Thread {
        Socket socket;

        alice(Socket socket) throws IOException {
            this.socket = socket;
            outputStream = new ObjectOutputStream(socket.getOutputStream());
            inputStream = new ObjectInputStream(socket.getInputStream());
            new listenAlice().start();
            new sendAlice().start();
        }
    }

    class listenAlice extends Thread {
        String inMessage;
        public void run() {
            while (!exit) {
                try {
                    inMessage = inputStream.readLine();

                } catch (IOException e) {
                    e.printStackTrace();
                }

                if (i == 0) {
                    if (inMessage != null) {
                        decryptAESKey(inMessage.getBytes());
                        System.out.println();
                        i++;
                    } else {
                        System.out.println("Error in decrypting AES key in clientThread.run()");
                        System.exit(1);
                    }
                } else {
                    if (inMessage != null) {
                        decryptMessage(inMessage.getBytes());
                    }
                }
            }
        }
    }

    class sendAlice extends Thread {
        String outMessage;
        public void run() {
            while (true) {
                try {
                    Scanner keyboardIn = new Scanner(System.in);
                    outputStream.writeBytes(encryptMessage(outMessage) + "\n");
                    write();
                }

                catch (Exception e) {
                    e.printStackTrace();
                    break;
                }
            }
        }

        public synchronized void write() throws IOException {
            outputStream.writeObject(messageToSend);
            outputStream.reset();
        }
    }

    private void decryptAESKey(byte[] encryptedKey) {
        SecretKey key = null;
        PrivateKey privKey = null;
        keyDecipher = null;
        try {
            privKey = readPrivateKeyFromFile("private.key"); // private key
            keyDecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // initialize the cipher...
            keyDecipher.init(Cipher.DECRYPT_MODE, privKey);
            key = new SecretKeySpec(keyDecipher.doFinal(encryptedKey), "AES");
            System.out.println();
            System.out.println(" AES key after decryption : " + key);
            i = 1;
            AESKey = key;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("exception decrypting the aes key: " + e.getMessage());
        }

    }

    private void decryptMessage(byte[] encryptedMessage) {
        ServerDecryptCipher = null;
        try {
            ServerDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            ServerDecryptCipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(IV.getBytes()));
            byte[] msg = ServerDecryptCipher.doFinal(encryptedMessage);
            System.out.println("Server: INCOMING Message From CLIENT >> " + new String(msg));
            System.out.println("Sever: Enter OUTGOING  message : > ");
        }

        catch (Exception e) {
            e.getCause();
            e.printStackTrace();
            System.out.println("Exception genereated in decryptData method. Exception Name  :" + e.getMessage());
        }
    }

    private byte[] encryptMessage(String s) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        ServerEncryptCipher = null;
        byte[] cipherText = null;
        ServerEncryptCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        ServerEncryptCipher.init(Cipher.ENCRYPT_MODE, AESKey, new IvParameterSpec(IV.getBytes()));
        cipherText = ServerEncryptCipher.doFinal(s.getBytes());

        return cipherText;
    }

    PrivateKey readPrivateKeyFromFile(String fileName) throws IOException {

        FileInputStream in = new FileInputStream(fileName);
        ObjectInputStream readObj = new ObjectInputStream(new BufferedInputStream(in));

        try {
            BigInteger m = (BigInteger) readObj.readObject();
            BigInteger d = (BigInteger) readObj.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, d);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey priKey = fact.generatePrivate(keySpec);
            return priKey;
        } catch (Exception e) {
            throw new RuntimeException("Some error in reading private key", e);
        } finally {
            readObj.close();
        }
    }

}
