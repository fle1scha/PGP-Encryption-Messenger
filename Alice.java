// NIS 2021
// Alice (Client) class that sends and receives data

import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.security.*;
import javax.crypto.*;

class Alice {
    static boolean exit = false;

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

}
