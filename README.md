# NIS Encryption Application Assignment
In the EncryptionApp directory, first run: <br>
`java Bob.java` <br>
If Bob successfully starts then you should see a confirmation, and Bob will wait for a connection from Alice.
In order to end the chat, type: exit
This will terminate the connection with Alice

Secondly, in a seperate terminal window, run: <br>
`java Alice.java`<br>
If Alice successfully starts then you should see a confirmation, and you will be prompted for input.
In order to end the chat, type: exit
This will terminate the connection with Bob

## Run Program
`java -cp bcprov-ext-jdk15on-169.jar Bob.java`


## Test Cases
I don't know how to run tests on this.
1. Alice sends multiple inputs in a row. PASS
2. Bob sends multiple inputs in a row. PASS
3. Alice sends inputs then exits. PASS
4. Bob sends inputs then exits. PASS
5. Chat in between Alice and Bob. PASS

## Using Java Security
https://www.tutorialspoint.com/java_cryptography/java_cryptography_quick_guide.htm
I implemented a signature, certificate, public and private key as an example in a simple application
The next step is to now try and implement that into our chat app
