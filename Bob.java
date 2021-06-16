// NIS 2021
// Bob (Server) Class that sends and receives data

import java.io.*;
import java.net.*;

class Bob
{
    public static void main(String[] args)
    {   
        try
        { 
        System.out.println("Bob has started his day.\nWaiting for Alice to call...");
        /* 
        Create Server Socket:
        A server socket waits for requests to come in over the network. 
        It performs some operation based on that request, and then returns a result to the requester.
        */
        int port = 888;
		ServerSocket serverSocket = new ServerSocket(port);
        String contactName = "Alice";

		/* 
        Connect to Client
        This class implements client sockets (also called just "sockets"). 
        A socket is an endpoint for communication between two machines.connect it to client socket
        */
		Socket Alice = serverSocket.accept(); //security manager's checkAccept method would get called here. 
		System.out.println("Connection established at "+ Alice);
        
		// to send data to the client
		PrintStream sendStream = new PrintStream(Alice.getOutputStream());

		// to read data coming from the client
		BufferedReader receieveReader = new BufferedReader(new InputStreamReader(Alice.getInputStream()));

		// to read data from the keyboard
		BufferedReader keyboardIn = new BufferedReader(new InputStreamReader(System.in));

		// server executes continuously
		while (true) 
            {

                String inMessage, outMessage;

                // repeat as long as the client
                // does not send a null string (can easily change this)

                // Read message from Alice
                while ((inMessage = receieveReader.readLine()) != null) {
                    System.out.println(contactName+": "+inMessage);
                    System.out.print("Bob: ");
                    outMessage = keyboardIn.readLine();

                    // Send message to Alice
                    sendStream.println(outMessage);
                }

                // close connection
                sendStream.close();
                receieveReader.close();
                keyboardIn.close();
                serverSocket.close();
                Alice.close();
            }
        } //try
        
        catch(IOException e)
        {
            System.out.println("Error "+ e.getMessage());
        }
    } 

}
