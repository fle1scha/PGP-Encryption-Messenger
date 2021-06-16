// NIS 2021
// Alice (Client) class that sends and receives data


import java.io.*;
import java.net.*;

class Alice {

	public static void main(String[] args)
	{
        try
        {
        System.out.println("Alice is out of bed.");
		// Create client socket
		Socket s = new Socket("localhost", 888);
        String contactName = "Bob";

		// to send data to the server
		DataOutputStream dos
			= new DataOutputStream(
				s.getOutputStream());

		// to read data coming from the server
		BufferedReader br
			= new BufferedReader(
				new InputStreamReader(
					s.getInputStream()));

		// to read data from the keyboard
		BufferedReader kb
			= new BufferedReader(
				new InputStreamReader(System.in));
		String str, str1;

		// repeat as long as exit
		// is not typed at client
        System.out.print("Alice: ");
		while (!(str = kb.readLine()).equals("exit")) {

			// send to the server
			dos.writeBytes(str + "\n");

			// receive from the server
			str1 = br.readLine();

			System.out.println(contactName+": "+str1);
            System.out.print("Alice: ");
		}

		// close connection.
		dos.close();
		br.close();
		kb.close();
		s.close();
    } //try

    catch (IOException e)
    {
        System.out.println("Error "+e.getMessage());

    }
	}

    
}
