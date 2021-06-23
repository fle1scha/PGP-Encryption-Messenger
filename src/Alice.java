// NIS 2021 - Encryption
// Alice (Client) class that sends and receives data

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
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
        }

        else {
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
                                int bytesRead;
                                int current = 0;
                                // read File
                                int FILE_SIZE = 6023380;
                                String FILE_TO_RECEIVE = "C:\\NISTestGet\\CaptureR.PNG";

                                byte[] mybytearray = new byte[FILE_SIZE];
                                InputStream is = s.getInputStream();
                                FileOutputStream fos = new FileOutputStream(FILE_TO_RECEIVE);
                                BufferedOutputStream bos = new BufferedOutputStream(fos);

                                bytesRead = is.read(mybytearray, 0, mybytearray.length);
                                current = bytesRead;

                                System.out.println("About to read");

                                // do {
                                // int counter = 0;
                                // System.out.println("Loop count " + counter + ", bytesread " + bytesRead + ",
                                // current " + current);
                                // bytesRead =
                                // is.read(mybytearray, current, (mybytearray.length-current));
                                // if(bytesRead >= 0) current += bytesRead;
                                //
                                // counter ++;
                                // } while(bytesRead > -1);

                                System.out.println("About to write");

                                bos.write(mybytearray, 0, current);
                                System.out.println("About to flush");
                                bos.flush();
                                System.out.println(
                                        "File " + FILE_TO_RECEIVE + " downloaded (" + current + " bytes read)");

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

}
