
//Create a Self-Signed Certificate using JSE and Bouncy Castle
//Antony Fleischer

//Java imports
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;

//Bouncy Castle imports
//Must include bc .jar(s) in project folder, and add them to referenenced libraries for VS Code. 
//Tutorials on the internet use deprecated methods so this is recent (2021).
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


//(called 'CertificateAuthority for an old assignment')
public class CertificateAuthority {

    public static void main(String[] args) throws Exception {

        // RSA Key Pair Generator using JSE
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA"); //create RSA KeyPairGenerator 
        kpGen.initialize(2048, new SecureRandom()); //Choose key strength
        KeyPair keyPair = kpGen.generateKeyPair(); //Generate private and public keys
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();

        //Information for Certificate
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG"); 
        X500Name issuer = new X500Name("CN=" + "ExampleIssuer"); // Issuer/Common Name
        X500Name subject = new X500Name("CN=" + "Client"); //Subject
        Date notBefore = new Date(); //The date which the certificate becomes effective. 
        long expiryDate = 1672437600000L; // expires 31 December 2022
        Date notAfter = new Date(expiryDate); //The date the certificate expires. 
        BigInteger serialNumber = BigInteger.valueOf(Math.abs(random.nextInt())); //Cert Serial Number

        //Define the generator
        X509v3CertificateBuilder certGenerator 
        = new JcaX509v3CertificateBuilder(
            issuer, 
            serialNumber, 
            notBefore,
            notAfter,
            subject,
            RSAPubKey
        );

        //Define how the certificate will be signed.
        //Usually with a hash algorithm and the Certificate Authority's private key. 
        //Change argument x in .build(x) to not self-sign the cert.
        final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1WithRSAEncryption").build(keyPair.getPrivate());

        //Generate a X.509 cert.
        X509CertificateHolder certificate = certGenerator.build(contentSigner);

        //Encode the certificate and write to a file. On Mac, you can open it with KeyChain Access
        //to confirm that it worked. 
        byte[] encodedCert = certificate.getEncoded();
        FileOutputStream fos = new FileOutputStream("Example.cert"); //Filename
        fos.write(encodedCert);
        fos.close();

    }
}