// NIS 2021 - Encryption
// Alice (Client) class that sends and receives data

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.*;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

class Alice {

    private static boolean exit = false;
    private static PrivateKey AlicePrivKey;
    private static PublicKey AlicePubKey;
    private static X509CertificateHolder certificate;
    private static PublicKey CAPubKey;
    private static PrivateKey CAPrivKey;
    private static PublicKey BobPubKey;

    public static void main(String[] args) throws Exception {
        File directory = new File("./certs");
        directory.mkdir();
        System.out.println("Generating public and private keys...");
        //// TimeUnit.SECONDS.sleep(1);
        genCertificate();
        // Create client socket
        System.out.println("Alice is connecting to Bob...");
        //// TimeUnit.SECONDS.sleep(1);
        Socket s = new Socket("localhost", 888);
        System.out.println("Connection established at " + s);
        String contactName = "Bob";

        // to send data to the server
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());

        // to read data coming from the server
        DataInputStream dis = new DataInputStream(s.getInputStream());

        // to read data from the keyboard
        Scanner keyboard = new Scanner(System.in);

        byte[] outmessageDigest = RSA.sign(CertificateAuthority.genDigest(certificate), CAPrivKey);
        byte[] certEncoded = certificate.getEncoded();

        // SETUP
        Security.setProperty("crypto.policy", "unlimited");

        //// TimeUnit.SECONDS.sleep(1);

        // Receive Message Digest
        int byteLength = dis.readInt();
        byte[] messageDigest = new byte[byteLength];
        dis.readFully(messageDigest);
        System.out.println("Bob message Digest received");
        //// TimeUnit.SECONDS.sleep(1);

        System.out.println("Sending message digest to Bob for TLS Handshake");
        dos.writeInt(outmessageDigest.length);
        dos.write(outmessageDigest);

        byteLength = dis.readInt();
        byte[] cert = new byte[byteLength];
        dis.readFully(cert);
        X509CertificateHolder BobCert = new X509CertificateHolder(cert);
        SubjectPublicKeyInfo tempCert = BobCert.getSubjectPublicKeyInfo();
        byte[] tempArray = tempCert.getEncoded();

        X509EncodedKeySpec spec = new X509EncodedKeySpec(tempArray);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        BobPubKey = kf.generatePublic(spec);

        System.out.println("Bob certificate received");
        //// TimeUnit.SECONDS.sleep(1);

        System.out.println("Sending certificate to Bob for TLS Handshake");
        dos.writeInt(certEncoded.length);
        dos.write(certEncoded);

        // Alice must now compare her message digest to Bob's message digest.
        byte[] AliceDigest = CertificateAuthority.genDigest(BobCert);

        if (RSA.authenticate(AliceDigest, messageDigest, CAPubKey)) {
            //// TimeUnit.SECONDS.sleep(1);
            System.out.println("Alice's digest matches Bob's.");
            if (certificate.getIssuer().equals(BobCert.getIssuer())) {
                //// TimeUnit.SECONDS.sleep(1);
                System.out.println("Alice trusts the CA of Bob's certificate.");
            }

        } else {
            System.out.println("This connection is not safe.");
            System.exit(0);
        }

        System.out.println("...");
        //// TimeUnit.SECONDS.sleep(1);
        System.out.println("...");
        //// TimeUnit.SECONDS.sleep(1);

        System.out.println("Initiating secure chat:");
        //// TimeUnit.SECONDS.sleep(1);
    
        Thread sendMessage = new Thread(new Runnable() {
            @Override
            public void run() {
                while (!exit) {

                    // read the message to deliver.

                    String msg = keyboard.nextLine();
                    byte[] encodedmsg = msg.getBytes(StandardCharsets.UTF_8);

                    byte[] PGPcipher;
                    try {

                        PGPcipher = PGP.encrypt(encodedmsg, BobPubKey, AlicePrivKey);
                        dos.writeInt(PGP.getIVLength());
                        dos.writeInt(PGP.getSessionKeyLength());
                        dos.writeInt(PGP.getAESLength());
                        dos.writeInt(PGP.getHashLength());
                        dos.writeInt(PGP.getMessageLength());
                        dos.writeInt(PGPcipher.length);
                        dos.write(PGPcipher);

                        if (msg.equals("exit")) {
                            exit = true;
                            System.out.println("You left the chat.");

                        }
                        // code for sending caption and image (can send other files as well)
                        else if (msg.equals("!F")) {
                            //Get details
                            System.out.println("Enter the path to your file:");
                            String filepath = keyboard.nextLine();
                            System.out.println("Enter your caption");
                            String caption = keyboard.nextLine();

                            // build message
                            Message message = buildMessage(filepath, caption);

                            // Compression
                            File compressedFile = compress(message);

                            // Send compressed file
                            sendFile(compressedFile, dos);
                            System.out.println("File sent.");

                            // Delete compressed file after sending since we don't need it
                            Files.deleteIfExists(compressedFile.toPath());
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                System.exit(0);
            }
        });
        // readMessage thread
        Thread readMessage = new Thread(new Runnable() {
            String inMessage;

            @Override
            public void run() {

                while (!exit) {
                    try {
                        // read the message sent to this client

                        if (!exit) {
                            int IVLength = dis.readInt();
                            int skLength = dis.readInt();
                            int AESLength = dis.readInt();
                            int hashLength = dis.readInt();
                            int messageLength = dis.readInt();
                            int length = dis.readInt();
                            byte[] inCipher = new byte[length];
                            dis.readFully(inCipher);
                            String plaintext = PGP.decrypt(inCipher, AlicePrivKey, BobPubKey, IVLength, skLength, AESLength, hashLength,
                                    messageLength);
                            // byte[] plaintext = AES.AESDecryption(AESdecrypt, sk, IV)
                            inMessage = plaintext.toString();
                            if (inMessage.equals("exit")) {
                                s.close();
                                exit = true;
                                System.out.println("Bob left the chat.");

                            } else if (inMessage.equals("!F")) {
                                // Receiving compressed file
                                try {

                                    //System.out.println(longsize);

                                    // Create Directory
                                    File directory = new File("./AliceReceived");
                                    directory.mkdir();

                                    File compressedFile = getCompressedFile(dis);
                                    decompressFile(compressedFile);

                                    //Delete temporary compressed file since we don't need it anymore
                                    Files.deleteIfExists(compressedFile.toPath());

                                } catch (IOException e) {
                                    e.printStackTrace();
                                }

                            } else {
                                System.out.println(contactName + ": " + inMessage);
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

    public static void genCertificate() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA"); // create RSA KeyPairGenerator
        kpGen.initialize(2048, new SecureRandom()); // Choose key strength
        KeyPair keyPair = kpGen.generateKeyPair(); // Generate private and public keys
        AlicePubKey = keyPair.getPublic(); // PubKey of the CA
        AlicePrivKey = keyPair.getPrivate();

        System.out.println("Populating certificate values...");
        //// TimeUnit.SECONDS.sleep(1);

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

    public static Message buildMessage(String filepath, String caption) {

        File file = new File(filepath);
        byte[] bytes = new byte[0];
        try {
            bytes = Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new Message(file.getName(), caption, bytes);
    }

    public static File compress(Message message) {
        File tempFile = null;
        try {
            tempFile = File.createTempFile("tmp", ".gz", new File("."));
//            System.out.println(tempFile);
            FileOutputStream f = new FileOutputStream(tempFile);
            GZIPOutputStream g = new GZIPOutputStream(f);
            ObjectOutputStream o = new ObjectOutputStream(g);

            o.writeObject(message);
            o.flush();
            System.out.println("Objects compressed");
            o.close();
            g.close();
            f.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

        return tempFile;
    }

    public static void sendFile(File compressedFile, DataOutputStream dos) {
        try {
            if (compressedFile != null) {
                long size = compressedFile.length();
                String strsize = Long.toString(size) + "\n"; //file size in bytes
                dos.writeBytes(strsize);
                FileInputStream fis = new FileInputStream(compressedFile);
                byte[] filebuffer = new byte[8192];
                int read = 0;
                while ((read = fis.read(filebuffer)) > 0) {
                    dos.write(filebuffer, 0, read);
                    dos.flush();
                }
                fis.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static File getCompressedFile(DataInputStream dis) {
        File compressedFile = null;
        try {
            String tempFilePath = "./AliceReceived/" + new Random().nextInt() + ".gz";
            String size = dis.readLine();
            long longsize = Long.parseLong(size);


            FileOutputStream fos = new FileOutputStream(tempFilePath);
            byte[] filebuffer = new byte[8192];
            int read = 0;
            long remaining = longsize;
            long fileBufferLen = filebuffer.length;

            while ((read = dis.read(filebuffer, 0, (int) Math.min(fileBufferLen, remaining))) > 0) {
                remaining -= read;
                fos.write(filebuffer, 0, read);
            }
            fos.close();

            compressedFile = new File(tempFilePath);
            System.out.println(compressedFile);
            System.out.println("Compressed object received");
        } catch (IOException e) {
            e.printStackTrace();
        }

        return compressedFile;
    }

    public static void decompressFile(File compressedFile) {
        try {
            System.out.println("Decompressing object");
            FileInputStream f = new FileInputStream(compressedFile);
            GZIPInputStream g = new GZIPInputStream(f);
            ObjectInputStream o = new ObjectInputStream(g);

            Message message = (Message) o.readObject();


            //Message Decompression into caption and image
            String fileName = message.filename;
            byte[] bytes = message.file;
            String caption = message.caption;

            // Write image to current directory
            File received = new File("./AliceReceived/" + fileName);
            OutputStream imageOutputStream = new FileOutputStream(received);
            imageOutputStream.write(bytes);
            System.out.println("Successfully extracted image. Caption: " + caption);
            imageOutputStream.close();

            o.close();
            g.close();
            f.close();

            System.out.println("The file was decompressed successfully!");
            // Delete compressed file after sending since we don't need it
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
        }
    }

}
