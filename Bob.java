// NIS 2021
// Bob (Server) Class that sends and receives data

import java.io.*;
import java.net.*;

class Bob {
    static boolean exit = false;

    public static void main(String[] args) throws IOException {

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
        PrintStream sendStream = new PrintStream(Alice.getOutputStream());

        // to read data coming from the client
        BufferedReader receieveReader = new BufferedReader(new InputStreamReader(Alice.getInputStream()));

        // to read data from the keyboard
        BufferedReader keyboardIn = new BufferedReader(new InputStreamReader(System.in));

        Thread sendMessage = new Thread(new Runnable() 
        {
            String outMessage;

            @Override
            public void run() {
                while (true && !exit) {



                    try {
                        outMessage = keyboardIn.readLine();

                        // Send message to Alice
                         sendStream.println(outMessage);

                         if (outMessage.equals("exit"))
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
            String inMessage;

            @Override
            public void run() {

                while (true && !exit)  {
                    try {
                        // read the message sent to this client
                        inMessage = receieveReader.readLine();
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
         * close connection sendStream.close(); receieveReader.close();
         * keyboardIn.close(); serverSocket.close(); Alice.close();
         */

    }

}
