
//Create a Self-Signed Certificate using JSE and Bouncy Castle
//Antony Fleischer

//Java imports
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Random;

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

    static PublicKey SubjectPubKey;
    static X500Name subject;
    static X509CertificateHolder certificate;
    static BigInteger serialNumber;
    static String filename;
    static X500Name issuer;
    static Date notBefore;
    long expiryDate;
    static Date notAfter;
    PublicKey CertPubKey;
    PrivateKey CertPrivKey;

    public CertificateAuthority() {

    }

    public X509CertificateHolder getCertificate() {
        return certificate;
    }

    public void setSubjectPubKey(PublicKey key) {
        SubjectPubKey = key;
    }

    public void setSubject(String name) {
        subject = new X500Name("CN=" + name);
    }

    public void generateSerial() {
        Random random = new SecureRandom();
        serialNumber = BigInteger.valueOf(Math.abs(random.nextInt()));
    }

    public void setOutFile(String file) {
        filename = file;
    }

    public PublicKey getCertPublicKey() {
        return CertPubKey;
    }

    public void setCertPrivateKey(PrivateKey key) {
        CertPrivKey = key;
    }

    public void setCertPublciKey(PrivateKey key) {
        CertPrivKey = key;
    }

    public void generateCert() throws Exception {

        // Define the generator
        X509v3CertificateBuilder certGenerator = new JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore,
                notAfter, subject, SubjectPubKey);

        // Define how the certificate will be signed.
        // Usually with a hash algorithm and the Certificate Authority's private key.
        // Change argument x in .build(x) to not self-sign the cert.
        final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1WithRSAEncryption").build(CertPrivKey);

        // Generate a X.509 cert.
        certificate = certGenerator.build(contentSigner);

        // Encode the certificate and write to a file. On Mac, you can open it with
        // KeyChain Access
        // to confirm that it worked.
        byte[] encodedCert = certificate.getEncoded();
        FileOutputStream fos = new FileOutputStream(filename); // Filename
        fos.write(encodedCert);
        fos.close();

    }

    public void populateCert() throws NoSuchAlgorithmException {
        // RSA Key Pair Generator using JSE
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA"); // create RSA KeyPairGenerator
        kpGen.initialize(2048, new SecureRandom()); // Choose key strength
        KeyPair keyPair = kpGen.generateKeyPair(); // Generate private and public keys
        CertPubKey = keyPair.getPublic(); // PubKey of the CA
        CertPrivKey = keyPair.getPrivate();
        // Information for Certificate

        issuer = new X500Name("CN=" + "ExampleIssuer"); // Issuer/Common Name
        notBefore = new Date(); // The date which the certificate becomes effective.
        expiryDate = 1672437600000L; // expires 31 December 2022
        notAfter = new Date(expiryDate); // The date the certificate expires.
    }

    public PublicKey setCAPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        CertPubKey = kf.generatePublic(spec);
        return CertPubKey;
    }

    public void setCAPrivateKey(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        CertPrivKey = kf.generatePrivate(spec);
    }

    public void savePubKey() throws IOException {
        byte[] encodedPubKey = CertPubKey.getEncoded();
        FileOutputStream fos = new FileOutputStream("CAPub.pem"); // Filename
        fos.write(encodedPubKey);
        fos.close();
    }

    public PrivateKey savePrivKey() throws IOException {
        byte[] encodedPrivKey = CertPrivKey.getEncoded();
        FileOutputStream fos = new FileOutputStream("CAPriv.pem"); // Filename
        fos.write(encodedPrivKey);
        fos.close();
        return CertPrivKey;
    }

    public static void main(String[] args) {
        System.out.println("This is the Certificate Authority class.");
    }

}