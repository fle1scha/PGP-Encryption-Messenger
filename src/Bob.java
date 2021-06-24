// NIS 2021
// Bob (Server) Class that sends and receives data

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

import java.security.*;

import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

import java.security.spec.X509EncodedKeySpec;

class Bob {
    static boolean exit = false;
    static PublicKey BobPubKey;
    static PrivateKey BobPrivKey;
    static X509CertificateHolder certificate;
    static PrivateKey CAPrivKey;
    static PublicKey CAPubKey;
    static PublicKey AlicePubKey;

    public static void main(String[] args) throws Exception {
        // Scanner to read data from the keyboard
        Scanner keyboard = new Scanner(System.in);

        Security.setProperty("crypto.policy", "unlimited");

        // Make directory to store certificates.
        File directory = new File("./certs");
        directory.mkdir();

        System.out.println("Generating public and private keys...");
        genCertificate();

        System.out.println("Bob is up and running.");
        System.out.println("Waiting for Alice to connect...");

        // Create Server Socket: A server socket waits for requests to come in over the
        // network
        int port = 888;
        ServerSocket serverSocket = new ServerSocket(port);
        Socket Alice = serverSocket.accept();
        System.out.println("Connection established at " + Alice);

        // DOS to send data to Alice.
        DataOutputStream dos = new DataOutputStream(Alice.getOutputStream());

        // DIS to read from Alice.
        DataInputStream dis = new DataInputStream(Alice.getInputStream());

        System.out.println("Signing message digest of certificate.");
        byte[] messageDigest = RSA.sign(RSA.genDigest(certificate), CAPrivKey);
        byte[] certEncoded = certificate.getEncoded();

        System.out.println("Sending message digest to Alice for TLS Handshake");
        dos.writeInt(messageDigest.length);
        dos.write(messageDigest);

        System.out.println("Receiving message digest from Alice");
        int byteLength = dis.readInt();
        byte[] inmessageDigest = new byte[byteLength];
        dis.readFully(inmessageDigest);

        System.out.println("Sending certifificate to Alice for TLS Handshake");
        dos.writeInt(certEncoded.length);
        dos.write(certEncoded);

        System.out.println("Receiving original certificate from Alice for message digest comparision");
        byteLength = dis.readInt();
        byte[] cert = new byte[byteLength];
        dis.readFully(cert);

        // Recreating Alice Public Key.
        X509CertificateHolder AliceCert = new X509CertificateHolder(cert);
        SubjectPublicKeyInfo tempCert = AliceCert.getSubjectPublicKeyInfo();
        byte[] tempArray = tempCert.getEncoded();
        X509EncodedKeySpec spec = new X509EncodedKeySpec(tempArray);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        AlicePubKey = kf.generatePublic(spec);

        System.out.println("Comparing message digests");
        byte[] BobDigest = RSA.genDigest(AliceCert);

        if (RSA.authenticate(BobDigest, inmessageDigest, CAPubKey)) {
            System.out.println("Bob's digest matches Alice's.");
            if (certificate.getIssuer().equals(AliceCert.getIssuer())) {
                System.out.println("Bob trusts the CA of Alice's certificate.");

            }

        } else {
            System.out.println(
                    "This connection is not safe. Your message digest did not match Alice's, or you do not already trust her CA.");
            System.exit(0);
        }

        System.out.println("Initiating secure chat:");

        for (int i = 0; i < 4; i++) {
            System.out.print(".");
            TimeUnit.MICROSECONDS.sleep(500000);
        }
        System.out.println("\nSecure chat ready:");

        // Send message thread
        Thread sendMessage = new Thread(new Runnable() {

            @Override
            public void run() {
                while (!exit) {

                    // Get input from keyboard.
                    String msg = keyboard.nextLine();
                    byte[] encodedmsg = msg.getBytes(StandardCharsets.UTF_8);
                    byte[] PGPcipher;

                    try {

                        // If Bob exits.
                        if (msg.equals("!EXIT")) {
                            dos.writeInt(0);
                            exit = true;
                            System.out.println("You left the chat.");
                            keyboard.close();
                            Alice.close();
                            serverSocket.close();
                        }

                        // If Bob wants to send a file.
                        else if (msg.equals("!FILE")) {
                            // Get details
                            System.out.println("Enter the path to your file:");
                            String filepath = keyboard.nextLine();
                            System.out.println("Enter your caption");
                            String caption = keyboard.nextLine();

                            Message message = Message.buildMessage(filepath, caption);
                            byte[] messageAsBytes = Message.messageToBytes(message);

                            PGPcipher = PGP.encrypt(messageAsBytes, AlicePubKey, BobPrivKey);
                            dos.writeInt(1);
                            dos.writeInt(PGP.getIVLength());
                            dos.writeInt(PGP.getSessionKeyLength());
                            dos.writeInt(PGP.getAESLength());
                            dos.writeInt(PGP.getHashLength());
                            dos.writeInt(PGP.getMessageLength());
                            dos.writeInt(PGPcipher.length);
                            dos.write(PGPcipher);

                            System.out.println("File sent.");

                        }

                        // If Bob sends a regular message.
                        else {
                            dos.writeInt(2);
                            PGPcipher = PGP.encrypt(encodedmsg, AlicePubKey, BobPrivKey);
                            dos.writeInt(PGP.getIVLength());
                            dos.writeInt(PGP.getSessionKeyLength());
                            dos.writeInt(PGP.getAESLength());
                            dos.writeInt(PGP.getHashLength());
                            dos.writeInt(PGP.getMessageLength());
                            dos.writeInt(PGPcipher.length);
                            dos.write(PGPcipher);
                            System.out.println("Message sent.");
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                System.exit(0);
            }
        });

        // Read message thread
        Thread readMessage = new Thread(new Runnable() {
            String inMessage;

            @Override
            public void run() {

                while (!exit) {
                    try {
                        int type = dis.readInt();

                        if (!exit) {

                            // If Alice exits.
                            if (type == 0) {
                                Alice.close();
                                exit = true;
                                System.out.println("Alice left the chat.");
                                System.exit(0);
                            }

                            // If Alice sends a file.
                            else if (type == 1) {
                                System.out.println("Receiving file");
                                int IVLength = dis.readInt();
                                int skLength = dis.readInt();
                                int AESLength = dis.readInt();
                                int hashLength = dis.readInt();
                                int messageLength = dis.readInt();
                                int length = dis.readInt();
                                byte[] inCipher = new byte[length];
                                dis.readFully(inCipher);
                                byte[] plaintext = PGP.decrypt(inCipher, BobPrivKey, AlicePubKey, IVLength, skLength,
                                        AESLength, hashLength, messageLength);

                                Message inMessage = Message.messageFromBytes(plaintext);

                                File directory = new File("./BobReceived");
                                directory.mkdir();

                                saveFile(inMessage);

                            }

                            // If Alice sends a normal message.
                            else if (type == 2) {
                                System.out.println("Receiving message.");
                                int IVLength = dis.readInt();
                                int skLength = dis.readInt();
                                int AESLength = dis.readInt();
                                int hashLength = dis.readInt();
                                int messageLength = dis.readInt();
                                int length = dis.readInt();
                                byte[] inCipher = new byte[length];
                                dis.readFully(inCipher);
                                byte[] plaintext = PGP.decrypt(inCipher, BobPrivKey, AlicePubKey, IVLength, skLength,
                                        AESLength, hashLength, messageLength);

                                inMessage = new String(plaintext, StandardCharsets.UTF_8);
                                System.out.println("Alice: " + inMessage);
                            }

                        }
                    } catch (Exception e) {

                        e.printStackTrace();
                    }
                }

                System.exit(0);
            }
        });

        readMessage.start();
        sendMessage.start();
    }

    // Generate a certificate.
    public static void genCertificate() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = kpGen.generateKeyPair();
        BobPubKey = keyPair.getPublic();
        BobPrivKey = keyPair.getPrivate();

        System.out.println("Populating certificate values...");

        CertificateAuthority CA = new CertificateAuthority();
        CA.setOutFile("./certs/Bob.cert");
        CA.setSubject("Bob");
        CA.generateSerial();
        CA.setSubjectPubKey(BobPubKey);

        CA.populateCert();

        CA.generateCert();
        certificate = CA.getCertificate();
        System.out.println("Bob certicate signed and generated. See Bob.cert");

        CAPubKey = CA.savePubKey();
        CAPrivKey = CA.savePrivKey();

    }

    // Save a file and output caption
    public static void saveFile(Message message) {
        try {
            String fileName = message.filename;
            byte[] bytes = message.file;
            String caption = message.caption;

            File received = new File("./BobReceived/" + fileName);
            OutputStream imageOutputStream = new FileOutputStream(received);
            imageOutputStream.write(bytes);
            System.out.println("Successfully extracted image. Caption: " + caption);
            imageOutputStream.close();
            System.out.println("The file was saved successfully!");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
