// NIS 2021
// Alice (Client) class that sends and receives data

import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;

class Alice {
    static boolean exit = false;
    private Cipher cipher1;
    private Cipher cipher2;
    int i = 0;
    static String IV = "placeholder";
    SecretKey AESkey;

    public static void main(String[] args) throws IOException {
        Security.setProperty("crypto.policy", "unlimited");

        System.out.println("Alice is out of bed.");
        // Create client socket
        Socket s = new Socket("localhost", 888);
        String contactName = "Bob";

        // to send data to the server
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());

        // to read data coming from the server
        BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));

        // to read data from the keyboard
        Scanner keyboard = new Scanner(System.in);
        
        Thread sendMessage = new Thread(new Runnable() 
        {
            @Override
            public void run() {
                while (true && !exit) {

                    // read the message to deliver.
                    String msg = keyboard.nextLine();

                    try {
                        // write on the output stream
                        dos.writeBytes(msg+"\n");

                        if (msg.equals("exit"))
                        {
                            exit = true;
                            System.out.println("You left the chat.");

                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                System.exit(0);
            }
        });
        // readMessage thread
        Thread readMessage = new Thread(new Runnable() 
        {
            @Override
            public void run() {

                while (true && !exit) {
                    try {
                        // read the message sent to this client
                        String inMessage = br.readLine();
                        if (!exit)
                        {
                            if (inMessage.equals("exit"))
                            {
                                s.close();
                                exit = true;
                                System.out.println("Bob left the chat.");
                                
                            }
                            else
                            {
                                System.out.println(contactName+": "+inMessage);
                            }
                        }
                        
                    } 
                    catch (IOException e) {

                        e.printStackTrace();
                    }
                }

                   
                System.exit(0);         }
        });

        sendMessage.start();
        readMessage.start();
    }

    void generateAESkey() throws NoSuchAlgorithmException {
        AESkey = null;
        KeyGenerator Gen = KeyGenerator.getInstance("AES");
        Gen.init(128);
        AESkey = Gen.generateKey();
        System.out.println("Genereated the AES key : " + AESkey);
    }

    private byte[] encryptAESKey() {
        cipher1 = null;
        byte[] key = null;
        try {
            PublicKey pK = readPublicKeyFromFile("public.key");
            System.out.println("Encrypting the AES key using RSA Public Key" + pK);
            // initialize the cipher with the user's public key
            cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            cipher1.init(Cipher.ENCRYPT_MODE, pK);
            long time1 = System.nanoTime();
            key = cipher1.doFinal(AESkey.getEncoded()); // this encrypted key will be sent to the server.
            long time2 = System.nanoTime();
            long totalRSA = time2 - time1;
            System.out.println("Time taken by RSA Encryption (Nano Seconds) : " + totalRSA);
            i = 1;
        }

        catch (Exception e) {
            System.out.println("exception encoding key: " + e.getMessage());
            e.printStackTrace();
        }
        return key;
    }

    private void decryptMessage(byte[] encryptedMessage) {
        cipher2 = null;
        try {
            cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher2.init(Cipher.DECRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()));
            byte[] msg = cipher2.doFinal(encryptedMessage);
            System.out.println("CLIENT: INCOMING Message From Server   >> " + new String(msg));
            System.out.println("CLIENT: Enter OUTGOING message > ");
        }

        catch (Exception e) {
            e.getCause();
            e.printStackTrace();
            System.out.println("Exception genereated in decryptData method. Exception Name  :" + e.getMessage());
        }
    }
    
    private byte[] encryptMessage(String s) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher2 = null;
        byte[] cipherText = null;
        cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        cipher2.init(Cipher.ENCRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()));
        long time3 = System.nanoTime();
        cipherText = cipher2.doFinal(s.getBytes());
        long time4 = System.nanoTime();
        long totalAES = time4 - time3;
        System.out.println("Time taken by AES Encryption (Nano Seconds) " + totalAES);
        return cipherText;
    }

    PublicKey readPublicKeyFromFile(String fileName) throws IOException {

        FileInputStream in = new FileInputStream(fileName);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));

        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpecifications = new RSAPublicKeySpec(m, e);

            KeyFactory kF = KeyFactory.getInstance("RSA");
            PublicKey pubK = kF.generatePublic(keySpecifications);
            return pubK;
        } catch (Exception e) {
            throw new RuntimeException("Some error in reading public key", e);
        } finally {
            oin.close();
        }
    }

}
