# NIS Encryption Application Assignment
Welcome to our implementation of PGP. Before running the program, please ensure that you have added
the Legion of the Bouncy Castle .jar files to your project's referenced libraries. 

After that, you can run the program from any IDE or VS Code. 

1. In Bob.java, run the program.
2. In a seperate terminal, run the Alice program program. You will be prompted to enter the IP address of Bob. 
3. Enter the IP address of Bob. This can be `localhost` if the programs are running on the same machine, or an internal IP address.
4. The system will them demonstrate how it exchanges and validates the certificates of Alice and Bob, before initiating a secure chat. 
5. In the chat, type a message and hit enter to send a regular message. 
6. To send a file, type `!FILE` and hit enter. You will be prompted for a file path and caption.
7. To exit, type `!EXIT`. 
8. Throughout the program's execution, the system will constantly tell the user the state of the PGP encryption process. 


Please note, that Bouncy Castle .jars were causing compilation issues, and that is why the program has to be run via an IDE. 

