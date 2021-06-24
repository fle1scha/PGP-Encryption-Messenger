// NIS 2021 - Encryption
// Alice (Client) class that sends and receives data

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

class Alice {

    static boolean exit = false;
    static SecretKey sk;
    static byte[] IV;
    static PrivateKey AlicePrivKey;
    static PublicKey AlicePubKey;
    static X509CertificateHolder certificate;
    static PublicKey CAPubKey;
    static PrivateKey CAPrivKey;
    static PublicKey BobPubKey;

    public static void main(String[] args) throws Exception {
        // Scanner to read data from the keyboard
        Scanner keyboard = new Scanner(System.in);

        Security.setProperty("crypto.policy", "unlimited");

        // Make directory to store certificates.
        File directory = new File("./certs");
        directory.mkdir();

        System.out.println("Generating public and private keys for Alice...");
        genCertificate();

        // Create client socket
        System.out.println("Enter the ip address of Bob:");
        String hostIP = keyboard.nextLine();
        System.out.println("Alice is connecting to Bob...");
        Socket s = new Socket(hostIP, 888);
        System.out.println("Connection established at " + s);

        // DOS to send data to Bob
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());

        // DIS to read data coming from Bob
        DataInputStream dis = new DataInputStream(s.getInputStream());

        System.out.println("Signing message digest of certificate.");
        byte[] outmessageDigest = RSA.sign(RSA.genDigest(certificate), CAPrivKey);
        byte[] certEncoded = certificate.getEncoded();

        System.out.println("Receiving message digest from Bob");
        int byteLength = dis.readInt();
        byte[] messageDigest = new byte[byteLength];
        dis.readFully(messageDigest);

        System.out.println("Sending message digest to Bob for TLS Handshake");
        dos.writeInt(outmessageDigest.length);
        dos.write(outmessageDigest);

        System.out.println("Receiving original certificate from Bob for message digest comparision");
        byteLength = dis.readInt();
        byte[] cert = new byte[byteLength];
        dis.readFully(cert);

        // Recreating Bob Public Key
        X509CertificateHolder BobCert = new X509CertificateHolder(cert);
        SubjectPublicKeyInfo tempCert = BobCert.getSubjectPublicKeyInfo();
        byte[] tempArray = tempCert.getEncoded();
        X509EncodedKeySpec spec = new X509EncodedKeySpec(tempArray);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        BobPubKey = kf.generatePublic(spec);

        System.out.println("Sending certificate to Bob for TLS Handshake");
        dos.writeInt(certEncoded.length);
        dos.write(certEncoded);

        System.out.println("Comparing message digests");
        byte[] AliceDigest = RSA.genDigest(BobCert);

        if (RSA.authenticate(AliceDigest, messageDigest, CAPubKey)) {
            System.out.println("Alice's digest matches Bob's.");
            if (certificate.getIssuer().equals(BobCert.getIssuer())) {
                System.out.println("Alice trusts the CA of Bob's certificate.");

            }

        } else {
            System.out.println(
                    "This connection is not safe. Your message digest did not match Bob's, or you do not already trust his CA.");
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

                        // If Alice exits.
                        if (msg.equals("!EXIT")) {
                            dos.writeInt(0);
                            exit = true;
                            System.out.println("You left the chat.");
                            keyboard.close();
                            //s.close();
                        }

                        // If Alice wants to send a file.
                        else if (msg.equals("!FILE")) {

                            System.out.println("Enter the path to your file:");
                            String filepath = keyboard.nextLine();
                            System.out.println("Enter your caption");
                            String caption = keyboard.nextLine();

                            Message message = Message.buildMessage(filepath, caption);

                            byte[] messageAsBytes = Message.messageToBytes(message);

                            PGPcipher = PGP.encrypt(messageAsBytes, BobPubKey, AlicePrivKey);
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

                        // If Alice sends a regular message.
                        else {
                            dos.writeInt(2);
                            PGPcipher = PGP.encrypt(encodedmsg, BobPubKey, AlicePrivKey);
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

                        if (!exit) {
                            int type = dis.readInt();

                            // If Bob exits.
                            if (type == 0) {
                                s.close();
                                exit = true;
                                System.out.println("Bob left the chat.");
                                System.exit(0);
                            }

                            // If Bob sends a file.
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
                                byte[] plaintext = PGP.decrypt(inCipher, AlicePrivKey, BobPubKey, IVLength, skLength,
                                        AESLength, hashLength, messageLength);

                                Message inMessage = Message.messageFromBytes(plaintext);

                                File directory = new File("./AliceReceived");
                                directory.mkdir();

                                saveFile(inMessage);
                            }

                            // If Bob sends a normal message.
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
                                byte[] plaintext = PGP.decrypt(inCipher, AlicePrivKey, BobPubKey, IVLength, skLength,
                                        AESLength, hashLength, messageLength);

                                inMessage = new String(plaintext, StandardCharsets.UTF_8);
                                System.out.println("Bob: " + inMessage);
                            }

                        }
                    } catch (Exception e) {

                        e.printStackTrace();
                    }
                }

                System.exit(0);
            }
        });

        sendMessage.start();
        readMessage.start();
    }

    // Generate a certificate.
    public static void genCertificate() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = kpGen.generateKeyPair();
        AlicePubKey = keyPair.getPublic();
        AlicePrivKey = keyPair.getPrivate();

        System.out.println("Populating certificate values...");

        CertificateAuthority CA = new CertificateAuthority();
        CA.setOutFile("./certs/Alice.cert");
        CA.setSubject("Alice");
        CA.generateSerial();
        CA.setSubjectPubKey(AlicePubKey);
        CAPubKey = CA.setCAPublicKey("./certs/CAPub.pem");
        CAPrivKey = CA.setCAPrivateKey("./certs/CAPriv.pem");
        CA.populateCert();

        CA.generateCert();
        certificate = CA.getCertificate();
        System.out.println("Alice certicate signed and generated. See Alice.cert");

    }

    // Save a file and output caption
    public static void saveFile(Message message) {
        try {

            String fileName = message.filename;
            byte[] bytes = message.file;
            String caption = message.caption;

            File received = new File("./AliceReceived/" + fileName);
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
