package voting_system;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;
//import java.util.SecureRandom;

public class Voter {
    public final String voterID;
    public final KeyPair keyPair;
    private final BigInteger p;
    private final BigInteger g;
    private BigInteger a;
    public BigInteger g_a;
    public SecretKey sessionKey;

    private BigInteger lastRA;
    private BigInteger receivedRB;

    public Voter(String id, BigInteger g, BigInteger p) throws Exception {
        this.voterID = id;
        this.g = g;
        this.p = p;
        this.keyPair = generateRSAKeyPair();
        regenerateDH();
    }

    public BigInteger generateNonce() {
        return new BigInteger(128, new SecureRandom());
    }

    public String respondToDHChallenge(Admin.DHChallenge challenge, PublicKey adminPublicKey) throws Exception {
        this.receivedRB = challenge.RB;

        // Verify signature of encrypted content
        boolean valid = CryptoUtil.verifySignature(
                challenge.encryptedPayload,
                Base64.getDecoder().decode(challenge.signature),
                adminPublicKey
        );
        if (!valid) {
            throw new SecurityException("Admin signature invalid.");
        }
        
        System.out.println(this.voterID + ": Received encrypted payload from admin = " + challenge.encryptedPayload);

        // Decrypt
        String decrypted = CryptoUtil.decryptWithRSA(challenge.encryptedPayload, this.keyPair.getPrivate());
        String[] parts = decrypted.split("\\|");
        BigInteger receivedRA = new BigInteger(parts[0]);
        BigInteger g_b = new BigInteger(parts[1]);
        
        System.out.println(this.voterID + ": Received RA from admin = " + receivedRA);

        if (!receivedRA.equals(this.lastRA)) {
            throw new SecurityException("RA mismatch.");
        }

        BigInteger Ks = g_b.modPow(this.a, p);
        this.sessionKey = CryptoUtil.deriveAESKey(Ks);
        
        System.out.println(this.voterID + ": Derived DH value using a,b in voter side = " + Ks);

        // Prepare response: encrypt and sign
        String payload = receivedRB + "|" + g_a;
        
        System.out.println(this.voterID + ": Received RB from admin = " + receivedRB);
        
        String encryptedPayload = CryptoUtil.encryptWithRSA(payload, adminPublicKey);
        String signatureBase64 = Base64.getEncoder().encodeToString(
                CryptoUtil.sign(encryptedPayload, keyPair.getPrivate())
        );
        
        System.out.println(this.voterID + ": Encrypted payload to admin = " + encryptedPayload);
        
        return encryptedPayload + "::" + signatureBase64;
    }

    public void setLastRA(BigInteger RA) {
        this.lastRA = RA;
    }

    private void regenerateDH() {
        this.a = new BigInteger(256, new SecureRandom());
        this.g_a = g.modPow(a, p);
    }

    private KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }
}
