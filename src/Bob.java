// NIS 2021
// Bob (Server) Class that sends and receives data

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.util.Random;
import java.util.Scanner;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

class Bob {
    private static boolean exit = false;
    private static PublicKey BobPubKey;
    private static PrivateKey BobPrivKey;
    private static X509CertificateHolder certificate;
    private static PrivateKey CAPrivKey;
    private static PublicKey CAPubKey;
    private static PublicKey AlicePubKey;

    public static void main(String[] args) throws Exception {
        File directory = new File("./certs");
        directory.mkdir();

        // Certificate Generation
        // ========================================================
        System.out.println("Generating public and private keys...");
        // TimeUnit.SECONDS.sleep(1);
        genCertificate();
        System.out.println("Bob is up and running.");
        // TimeUnit.SECONDS.sleep(1);
        System.out.println("Waiting for Alice to connect...");
        /*
         * Create Server Socket: A server socket waits for requests to come in over the
         * network. It performs some operation based on that request, and then returns a
         * result to the requester.
         */
        int port = 888;
        ServerSocket serverSocket = new ServerSocket(port);
        String contactName = "Alice";

        /*
         * Connect to Client This class implements client sockets (also called just
         * "sockets"). A socket is an endpoint for communication between two
         * machines.connect it to client socket
         */
        Socket Alice = serverSocket.accept(); // security manager's checkAccept method would get called here.
        System.out.println("Connection established at " + Alice);

        // to send data to the client
        DataOutputStream dos = new DataOutputStream(Alice.getOutputStream());

        // to read data coming from the client
        DataInputStream dis = new DataInputStream(Alice.getInputStream());

        // to read data from the keyboard
        Scanner keyboard = new Scanner(System.in);

        byte[] messageDigest = RSA.sign(CertificateAuthority.genDigest(certificate), CAPrivKey);
        byte[] certEncoded = certificate.getEncoded();

        System.out.println("Sending message digest to Alice for TLS Handshake");
        dos.writeInt(messageDigest.length);
        dos.write(messageDigest);

        // Receive Message Digest
        int byteLength = dis.readInt();
        byte[] inmessageDigest = new byte[byteLength];
        dis.readFully(inmessageDigest);
        System.out.println("Alice message Digest received");
        // TimeUnit.SECONDS.sleep(1);

        System.out.println("Sending certifificate to Alice for TLS Handshake");
        dos.writeInt(certEncoded.length);
        dos.write(certEncoded);

        byteLength = dis.readInt();
        byte[] cert = new byte[byteLength];
        dis.readFully(cert);
        X509CertificateHolder AliceCert = new X509CertificateHolder(cert);
        SubjectPublicKeyInfo tempCert = AliceCert.getSubjectPublicKeyInfo();
        byte[] tempArray = tempCert.getEncoded();

        X509EncodedKeySpec spec = new X509EncodedKeySpec(tempArray);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        AlicePubKey = kf.generatePublic(spec);
        System.out.println("Alice certificate received");
        // TimeUnit.SECONDS.sleep(1);

        // Bob must now compare her message digest to Bob's message digest.
        byte[] BobDigest = CertificateAuthority.genDigest(AliceCert);

        if (RSA.authenticate(BobDigest, inmessageDigest, CAPubKey)) {
            // TimeUnit.SECONDS.sleep(1);
            System.out.println("Bob's digest matches Alice's.");
            if (certificate.getIssuer().equals(AliceCert.getIssuer())) {
                // TimeUnit.SECONDS.sleep(1);
                System.out.println("Bob trusts the CA of Alice's certificate.");

            }

        } else {
            System.out.println("This connection is not safe.");
            System.exit(0);
        }

        System.out.println("...");
        // TimeUnit.SECONDS.sleep(1);
        System.out.println("...");
        // TimeUnit.SECONDS.sleep(1);
        System.out.println("Initiating secure chat...");
        // TimeUnit.SECONDS.sleep(1);

        Thread sendMessage = new Thread(new Runnable() {

            @Override
            public void run() {
                while (!exit) {

                    String msg = keyboard.nextLine();
                    byte[] encodedmsg = msg.getBytes(StandardCharsets.UTF_8);
                    byte[] PGPcipher;

                    try {

                        PGPcipher = PGP.encrypt(encodedmsg, AlicePubKey, BobPrivKey);
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
                        if (!exit) {
                            int IVLength = dis.readInt();
                            int skLength = dis.readInt();
                            int AESLength = dis.readInt();
                            int hashLength = dis.readInt();
                            int messageLength = dis.readInt();
                            int length = dis.readInt();
                            byte[] inCipher = new byte[length];
                            dis.readFully(inCipher);
                            String plaintext = PGP.decrypt(inCipher, BobPrivKey, AlicePubKey, IVLength, skLength, AESLength, hashLength,
                                    messageLength);
                            // byte[] plaintext = AES.AESDecryption(AESdecrypt, sk, IV)
                            inMessage = plaintext.toString();

                            if (inMessage.equals("exit")) {
                                Alice.close();
                                exit = true;
                                System.out.println("Alice left the chat.");
                            } else if (inMessage.equals("!F")) {
                                // Receiving compressed file
                                try {

                                    //System.out.println(longsize);

                                    // Create Directory
                                    File directory = new File("./BobReceived");
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
                keyboard.close();
                System.exit(0);
            }
        });

        readMessage.start();
        sendMessage.start();

    }

    public static void genCertificate() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA"); // create RSA KeyPairGenerator
        kpGen.initialize(2048, new SecureRandom()); // Choose key strength
        KeyPair keyPair = kpGen.generateKeyPair(); // Generate private and public keys
        BobPubKey = keyPair.getPublic(); // PubKey of the CA
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
            String tempFilePath = "./BobReceived/" + new Random().nextInt() + ".gz";
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
            File received = new File("./BobReceived/" + fileName);
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
