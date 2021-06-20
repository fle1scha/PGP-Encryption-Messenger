// NIS 2021
// Bob (Server) Class that sends and receives data

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Scanner;
import javax.crypto.*;

class Bob {
    static boolean exit = false;

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        /*
        *This will instantiate the RSA object to create both public and private keys
        *They will be saved as private.key and public.key 
        */
        RSA rsa = new RSA();
        rsa.createRSA();
        
        /*
        Security.setProperty("crypto.policy", "unlimited");
        Just testing whether the configuration works properly, should print
        2147483647
        try {
            int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
            System.out.println("Max Key Size for AES : " + maxKeySize);
        } catch (Exception e) {
        }
        */

        System.out.println("Bob has started his day.\nWaiting for Alice to call...");
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
        DataOutputStream sendStream = new DataOutputStream(Alice.getOutputStream());

        // to read data coming from the client
        DataInputStream dis = new DataInputStream((Alice.getInputStream()));

        // to read data from the keyboard
        Scanner keyboardIn = new Scanner(System.in);

        Thread sendMessage = new Thread(new Runnable() {
            String outMessage;

            @Override
            public void run() {
                while (!exit) {

                    try {
                        outMessage = keyboardIn.nextLine();
                        // Send message to Alice
                        sendStream.writeBytes(outMessage + "\n");

                        if (outMessage.equals("exit")) {
                            exit = true;
                            System.out.println("You left the chat.");
                        }

                        else if (outMessage.equals("!F")) {
                            String FILE_TO_SEND = "C:\\NISTestSend\\Capture.PNG";
                            //send File
                            File myFile = new File (FILE_TO_SEND);
                            byte [] mybytearray  = new byte [(int)myFile.length()];
                            FileInputStream fis = new FileInputStream(myFile);
                            BufferedInputStream bis = new BufferedInputStream(fis);
                            bis.read(mybytearray,0,mybytearray.length);
                            OutputStream os = Alice.getOutputStream();
                            System.out.println("Sending " + FILE_TO_SEND + "(" + mybytearray.length + " bytes)");
                            os.write(mybytearray,0,mybytearray.length);
                            os.flush();
                            System.out.println("Done.");
                        }

                    } catch (IOException e) {
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
                        inMessage = dis.readLine();
                        if (!exit)
                        {
                        if (inMessage.equals("exit"))
                        {
                            Alice.close();
                            exit = true;
                            System.out.println("Alice left the chat.");
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

                System.exit(0);
            }
        });

        readMessage.start();
        sendMessage.start();

        /*
         * close connection sendStream.close(); dis.close();
         * keyboardIn.close(); serverSocket.close(); Alice.close();
         */

    }

}
