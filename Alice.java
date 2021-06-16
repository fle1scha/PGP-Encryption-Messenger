// NIS 2021
// Alice (Client) class that sends and receives data

import java.io.*;
import java.net.*;
import java.util.Scanner;

class Alice {
    static boolean exit = false;

    public static void main(String[] args) throws IOException {

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

        Thread sendMessage = new Thread(new Runnable() {
            String outMessage;

            @Override
            public void run() {
                while (true && !exit) {

                    try {

                        outMessage = keyboard.nextLine();
                        dos.writeBytes(outMessage + "\n");

                        if (outMessage.equals("exit")) {
                            exit = true;
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                System.out.println("You left the chat.");
                System.exit(0);
            }
        });
        // readMessage thread
        Thread readMessage = new Thread(new Runnable() {
            String inMessage;

            @Override
            public void run() {

                while (true && !exit) {
                    try {

                        String inMessage = br.readLine();

                        if (inMessage.equals("exit") || !exit) {
                            exit = true;
                            s.close();
                        } else {
                            System.out.println(contactName + ": " + inMessage);
                        }
                    } catch (IOException e) {

                        e.printStackTrace();
                    }
                }

                System.out.println("Bob left the chat.");
                System.exit(0);
            }
        });

        sendMessage.start();
        readMessage.start();
    }

}
