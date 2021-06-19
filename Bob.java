// NIS 2021
// Bob (Server) Class that sends and receives data

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import javax.crypto.*;
import java.math.BigInteger;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Bob {
    static boolean exit = false;
    static String IV = "placeholder";
    int i;
    private Cipher keyDecipher;
    SecretKey AESKey;
    private Cipher ServerDecryptCipher;
	private Cipher ServerEncryptCipher;

    public static void main(String[] args) throws IOException {
        // Just testing whether the configuration works properly
        Security.setProperty("crypto.policy", "unlimited");        
        try {
            int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
            System.out.println("Max Key Size for AES : " + maxKeySize);
        } catch (Exception e) {
        }

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

        Thread sendMessage = new Thread(new Runnable() {
            String outMessage;

            @Override
            public void run() {
                while (true && !exit) {

                    try {
                        outMessage = keyboardIn.readLine();

                        // Send message to Alice
                        sendStream.println(outMessage);

                        if (outMessage.equals("exit")) {
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
        Thread readMessage = new Thread(new Runnable() {
            String inMessage;

            @Override
            public void run() {

                while (true && !exit) {
                    try {
                        // read the message sent to this client
                        inMessage = receieveReader.readLine();
                        if (!exit) {
                            if (inMessage.equals("exit")) {
                                Alice.close();
                                exit = true;
                            } else {
                                System.out.println(contactName + ": " + inMessage);
                            }
                        }
                    } catch (IOException e) {

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

    private void decryptAESKey(byte[] encryptedKey) {
	        SecretKey key = null; PrivateKey privKey = null; keyDecipher = null;
	        try
	        {
	            privKey = readPrivateKeyFromFile("private.key"); 			//  private key
	            keyDecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 		// initialize the cipher...
	            keyDecipher.init(Cipher.DECRYPT_MODE, privKey );
	            key = new SecretKeySpec (keyDecipher.doFinal(encryptedKey), "AES");
	            System.out.println();
	            System.out.println(" AES key after decryption : " + key);
	            i = 1;
	            AESKey =  key;
	        }
	        catch(Exception e)
	         {  e.printStackTrace(); 
	        	System.out.println ( "exception decrypting the aes key: "  + e.getMessage() );
	             }
	       
	    }

        private void decryptMessage(byte[] encryptedMessage) {
	        ServerDecryptCipher = null;
	        try
	        {
	            ServerDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	            ServerDecryptCipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(IV.getBytes()));
	             byte[] msg = ServerDecryptCipher.doFinal(encryptedMessage);		            
	             System.out.println("Server: INCOMING Message From CLIENT >> " + new String(msg));
	             System.out.println("Sever: Enter OUTGOING  message : > ");
	        }
	        
	        catch(Exception e)
	         {
	        	e.getCause();
	        	e.printStackTrace();
	        	System.out.println ( "Exception genereated in decryptData method. Exception Name  :"  + e.getMessage() );
	            }
	    }

        private byte[] encryptMessage(String s)
                throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
            ServerEncryptCipher = null;
            byte[] cipherText = null;
            ServerEncryptCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            ServerEncryptCipher.init(Cipher.ENCRYPT_MODE, AESKey, new IvParameterSpec(IV.getBytes()));
            cipherText = ServerEncryptCipher.doFinal(s.getBytes());

            return cipherText;
        }

        PrivateKey readPrivateKeyFromFile(String fileName) throws IOException {
			
			 FileInputStream in = new FileInputStream(fileName);
		  	ObjectInputStream readObj =  new ObjectInputStream(new BufferedInputStream(in));

		  	try {
		  	  BigInteger m = (BigInteger) readObj.readObject();
		  	  BigInteger d = (BigInteger) readObj.readObject();
		  	  RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, d);
		  	  KeyFactory fact = KeyFactory.getInstance("RSA");
		  	  PrivateKey priKey = fact.generatePrivate(keySpec);
		  	  return priKey;
		  	} catch (Exception e) {
		  		  throw new RuntimeException("Some error in reading private key", e);
		  	} finally {
		 	   readObj.close();
		 	 }
			}

    }


