import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;
import javax.crypto.*;

public class KeyPairGenertor {
    public static void main(String args[]) throws Exception {
        // Accepting text from user
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter some text");
        String msg = sc.nextLine();

        // Creating KeyPair generator object
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");

        // Initializing the KeyPairGenerator
        keyPairGen.initialize(2048);

        // Generating the pair of keys
        KeyPair pair = keyPairGen.generateKeyPair();

        // Getting the private key from the key pair
        PrivateKey privKey = pair.getPrivate();

        // Creating a Signature object
        Signature sign = Signature.getInstance("SHA256withDSA");

        // Initialize the signature
        sign.initSign(privKey);

        byte[] bytes = "Hello how are you".getBytes();

        // Adding data to the signature
        sign.update(bytes);

        // Calculating the signature
        byte[] signature = sign.sign();

        // Initilaising the signatyre
        sign.initVerify(pair.getPublic());
        sign.update(bytes);

        // Verify signature
        boolean bool = sign.verify(signature);

        if (bool) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature failed");
        }

        // Getting the public key from the key pair
        PublicKey publicKey = pair.getPublic();
        //System.out.println("Keys generated");

        // Printing the signature
        System.out.println("Digital signature for given text: " + new String(signature, "UTF8"));

    }
}