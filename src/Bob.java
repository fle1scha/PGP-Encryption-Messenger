// NIS 2021
// Bob (Server) Class that sends and receives data

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import javax.crypto.*;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;

class Bob {
    static boolean exit = false;
    static PublicKey BobPubKey;
    static PrivateKey BobPrivKey;
    static X509CertificateHolder certificate;
    static PrivateKey CAPrivKey;
    static PublicKey CAPubKey;
    static PublicKey AlicePubKey;

    public static void main(String[] args) throws Exception {

        // Certificate Generation
        // ========================================================
        System.out.println("Generating public and private keys...");
        //TimeUnit.SECONDS.sleep(1);
        genCertificate();
        System.out.println("Bob is up and running.");
        //TimeUnit.SECONDS.sleep(1);
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

        byte[] messageDigest = RSA.sign(genDigest(certificate), CAPrivKey);
        byte[] certEncoded = certificate.getEncoded();

        System.out.println("Sending message digest to Alice for TLS Handshake");
        dos.writeInt(messageDigest.length);
        dos.write(messageDigest);

        
        // Receive Message Digest
        int byteLength = dis.readInt();
        byte[] inmessageDigest = new byte[byteLength];
        dis.readFully(inmessageDigest);
        System.out.println("Alice message Digest received");
        //TimeUnit.SECONDS.sleep(1);

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
        //TimeUnit.SECONDS.sleep(1);

        // Bob must now compare her message digest to Bob's message digest.
        byte[] BobDigest = genDigest(AliceCert);

        if (RSA.authenticate(BobDigest, inmessageDigest, CAPubKey)) {
            //TimeUnit.SECONDS.sleep(1);
            System.out.println("Bob's digest matches Alice's.");
            if (certificate.getIssuer().equals(AliceCert.getIssuer())) {
                //TimeUnit.SECONDS.sleep(1);
                System.out.println("Bob trusts the CA of Alice's certificate.");

            }

        }

        else {
            System.out.println("This connection is not safe.");
            System.exit(0);
        }

        System.out.println("...");
        //TimeUnit.SECONDS.sleep(1);
        System.out.println("...");
        //TimeUnit.SECONDS.sleep(1);
        System.out.println("Initiating secure chat...");
        //TimeUnit.SECONDS.sleep(1);

        

        Thread sendMessage = new Thread(new Runnable() {
            

            @Override
            public void run() {
                while (!exit) {

                    String msg = keyboard.nextLine();
                    byte[] encodedmsg = msg.getBytes(StandardCharsets.UTF_8);
                    byte[] PGPcipher;
                    
                    try {
                        // write on the output stream
                        //AEScipher = AES.AESEncryption(msg, sk, IV);
                        System.out.println("Original Message: " + msg);
                        //System.out.println("AES Encrypted Message: " + AEScipher);
                        PGPcipher = PGP.encrypt(encodedmsg, AlicePubKey, BobPrivKey);
                        System.out.println("PGP encrypted message: "+PGPcipher);
        
                        dos.writeInt(PGP.getHashLength());
                        dos.writeInt(PGP.getMessageLength());
                        dos.writeInt(PGPcipher.length);
                        dos.write(PGPcipher);

                        if (msg.equals("exit")) {
                            exit = true;
                            System.out.println("You left the chat.");
                        }

                        else if (msg.equals("!F")) {
                            String FILE_TO_SEND = "C:\\NISTestSend\\Capture.PNG";
                            // send File
                            File myFile = new File(FILE_TO_SEND);
                            byte[] mybytearray = new byte[(int) myFile.length()];
                            FileInputStream fis = new FileInputStream(myFile);
                            BufferedInputStream bis = new BufferedInputStream(fis);
                            bis.read(mybytearray, 0, mybytearray.length);
                            OutputStream os = Alice.getOutputStream();
                            System.out.println("Sending " + FILE_TO_SEND + "(" + mybytearray.length + " bytes)");
                            os.write(mybytearray, 0, mybytearray.length);
                            os.flush();
                            System.out.println("Done.");
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
                            int hashLength = dis.readInt();
                            int messageLength = dis.readInt();
                            int length = dis.readInt();
                            byte[] inCipher = new byte[length];
                            dis.readFully(inCipher);
                            String plaintext = PGP.decrypt(inCipher, BobPrivKey, AlicePubKey, hashLength, messageLength);
                            // byte[] plaintext = AES.AESDecryption(AESdecrypt, sk, IV)
                            inMessage = plaintext.toString();

                            if (inMessage.equals("exit")) {
                                Alice.close();
                                exit = true;
                                System.out.println("Alice left the chat.");
                            } else {
                                System.out.println(contactName + ": " + inMessage);
                            }
                        }
                    } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | SignatureException | InterruptedException e) {

                        e.printStackTrace();
                    }
                }

                System.exit(0);
            }
        });

        readMessage.start();
        sendMessage.start();

        /*
         * close connection dos.close(); dis.close(); keyboardIn.close();
         * serverSocket.close(); Alice.close();
         */

    }

    /*
     * // ================= Read private Key from the file=======================
     * 
     * readPrivateKeyFromFile method reads the RSA private key from private.key file
     * saved in same directory. the private key is used to decrypt/decipher the AES
     * key sent by Client.
     * 
     * 
     * 
     */

    PrivateKey readPrivateKey(String fileName) throws IOException {
        FileInputStream in = new FileInputStream(fileName);
        ObjectInputStream readObj = new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) readObj.readObject();
            BigInteger d = (BigInteger) readObj.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, d);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = fact.generatePrivate(keySpec);
            return privateKey;
        } catch (Exception e) {
            throw new RuntimeException("Some error in reading private key", e);
        } finally {
            readObj.close();
        }
    }

    public static void genCertificate() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA"); // create RSA KeyPairGenerator
        kpGen.initialize(2048, new SecureRandom()); // Choose key strength
        KeyPair keyPair = kpGen.generateKeyPair(); // Generate private and public keys
        BobPubKey = keyPair.getPublic(); // PubKey of the CA
        BobPrivKey = keyPair.getPrivate();

        System.out.println("Populating certificate values...");
        ////TimeUnit.SECONDS.sleep(1);

        CertificateAuthority CA = new CertificateAuthority();
        CA.setOutFile("./certs/Bob.cert");
        CA.setSubject("Bob");
        CA.generateSerial();
        CA.setSubjectPubKey(BobPubKey);

        CA.populateCert();

        CA.generateCert();
        certificate = CA.getCertificate();
        System.out.println("Bob certicate signed and generated. See Bob.cert");
        ////TimeUnit.SECONDS.sleep(1);

        CAPubKey = CA.savePubKey();
        CAPrivKey = CA.savePrivKey();

    }

    public static byte[] genDigest(X509CertificateHolder cert) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InterruptedException {
        System.out.println("Calculating digest...");
        TimeUnit.SECONDS.sleep(2);
        byte[] input = cert.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(input);
        byte[] digest = md.digest();
        return digest;

    }

}
