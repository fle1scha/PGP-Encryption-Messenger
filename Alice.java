// NIS 2021
// Alice (Client) class that sends and receives data

import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.Scanner;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;


class Alice {

    public static SecretKey generateSecretAESKey() throws Exception{

        // Generate Secret Key
        // ========================================================
        SecureRandom sr = new SecureRandom();
        byte b [] = new byte[20];
        sr.nextBytes(b);

  
        KeyGenerator kg = KeyGenerator.getInstance( "AES" );
        kg.init(256, sr);
        SecretKey key = kg.generateKey();
        return key;
        }
        // ========================================================

        // Execute AES Encryption
        // ========================================================

        public static byte[] executeAESEncryption(String plain_text,SecretKey sk,byte[] IV)throws Exception
        {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
            c.init(Cipher.ENCRYPT_MODE,sk,ivParameterSpec);
            return c.doFinal(plain_text.getBytes());
        }
        // ========================================================

        // Execute AES Decryption
        // ========================================================

        public static String executeAESDecryption(byte[] cipher_text,SecretKey sk,byte[] IV)throws Exception
        {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            IvParameterSpec ivParameterSpec= new IvParameterSpec(IV);
      
            c.init(Cipher.DECRYPT_MODE,sk,ivParameterSpec);
            byte[] result= c.doFinal(cipher_text);
            return new String(result);
        }
        // ========================================================

        public static byte[] createInitializationVector()
        {
      
            // Used with encryption
            byte[] initializationVector
                = new byte[16];
            SecureRandom secureRandom
                = new SecureRandom();
            secureRandom.nextBytes(initializationVector);
            return initializationVector;
        }

    static boolean exit = false;

    public static void main(String[] args) throws IOException {

        // Generating Secret Key
        // ========================================================

        try {
            SecretKey sk = generateSecretAESKey();
            System.out.println(" -- Secret key generated ...");
            System.out.println(" -- Converting secret key ...");
            String encodedKey = Base64.getEncoder().encodeToString(sk.getEncoded());
            System.out.println(" -- Secret Key: " + encodedKey);
        } catch (Exception e1) {
            e1.printStackTrace();
        }

        // ========================================================



        Security.setProperty("crypto.policy", "unlimited");

        System.out.println("Alice is out of bed.");
        // Create client socket
        Socket s = new Socket("localhost", 888);
        String contactName = "Bob";

        // to send data to the server
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());

        // to read data coming from the server
        DataInputStream dis = new DataInputStream(s.getInputStream());

        // to read data from the keyboard
        Scanner keyboard = new Scanner(System.in);






        
        Thread sendMessage = new Thread(new Runnable() 
        {
            @Override
            public void run() {
                while (!exit) {

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

                while (!exit) {
                    try {
                        // read the message sent to this client
                        String inMessage = dis.readLine();
                        if (!exit)
                        {
                            if (inMessage.equals("exit"))
                            {
                                s.close();
                                exit = true;
                                System.out.println("Bob left the chat.");
                                
                            }
                            else if (inMessage.equals("!F")) {
                                int bytesRead;
                                int current = 0;
                                //read File
                                int FILE_SIZE = 6023380;
                                String FILE_TO_RECEIVE = "C:\\NISTestGet\\CaptureR.PNG";

                                byte [] mybytearray  = new byte [FILE_SIZE];
                                InputStream is = s.getInputStream();
                                FileOutputStream fos = new FileOutputStream(FILE_TO_RECEIVE);
                                BufferedOutputStream bos = new BufferedOutputStream(fos);

                                bytesRead = is.read(mybytearray,0,mybytearray.length);
                                current = bytesRead;

                                System.out.println("About to read");

//                                do {
//                                    int counter = 0;
//                                    System.out.println("Loop count " + counter + ", bytesread " + bytesRead + ", current " + current);
//                                    bytesRead =
//                                            is.read(mybytearray, current, (mybytearray.length-current));
//                                    if(bytesRead >= 0) current += bytesRead;
//
//                                    counter ++;
//                                } while(bytesRead > -1);

                                System.out.println("About to write");

                                bos.write(mybytearray, 0 , current);
                                System.out.println("About to flush");
                                bos.flush();
                                System.out.println("File " + FILE_TO_RECEIVE
                                        + " downloaded (" + current + " bytes read)");

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


}
