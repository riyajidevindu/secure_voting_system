package voting_system;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;
import java.util.Random;
//import java.util.SecureRandom;

public class Voter {
    // Helper method for formatted voter printing
    private void printVoter(String message) {
        System.out.println();
        System.out.println("[VOTER-" + voterID + "] " + message);
    }
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
        
        printVoter("Received encrypted payload from admin = " + challenge.encryptedPayload);

        // Decrypt
        String decrypted = CryptoUtil.decryptWithRSA(challenge.encryptedPayload, this.keyPair.getPrivate());
        String[] parts = decrypted.split("\\|");
        BigInteger receivedRA = new BigInteger(parts[0]);
        BigInteger g_b = new BigInteger(parts[1]);
        printVoter("Received RA from admin = " + receivedRA);

        if (!receivedRA.equals(this.lastRA)) {
            throw new SecurityException("RA mismatch.");
        }

        BigInteger Ks = g_b.modPow(this.a, p);
        this.sessionKey = CryptoUtil.deriveAESKey(Ks);
        printVoter("Derived DH value using a,b in voter side = " + Ks);

        // Prepare response: encrypt and sign
        String payload = receivedRB + "|" + g_a;
        
        printVoter("Received RB from admin = " + receivedRB);
        
        String encryptedPayload = CryptoUtil.encryptWithRSA(payload, adminPublicKey);
        String signatureBase64 = Base64.getEncoder().encodeToString(
                CryptoUtil.sign(encryptedPayload, keyPair.getPrivate())
        );
        printVoter("Encrypted payload to admin = " + encryptedPayload);
        return encryptedPayload + "::" + signatureBase64;
    }
    
    public String prepareEncryptedVote(String encryptedCandidateList) throws Exception {
        if (sessionKey == null) {
            throw new IllegalStateException("Session key not set for voter " + voterID);
        }

        // Decrypt candidate list
        printVoter("Received encrypted candidate list = " + encryptedCandidateList);
        String csvCandidates = CryptoUtil.decryptWithAES(encryptedCandidateList, sessionKey);
        String[] candidates = csvCandidates.split(",");
        if (candidates.length == 0) {
            throw new IllegalStateException("No candidates received");
        }
        printVoter("Received decrypted candidate list = " + csvCandidates);
        Random rand = new Random();
        // Select a candidate randomly (simulation)
        String selected = candidates[rand.nextInt(candidates.length)];
        printVoter("Selected candidate = " + selected);
        // Hash and encrypt vote
        String hashedVote = CryptoUtil.sha256(selected);
        printVoter("Hashed value of the vote = " + hashedVote);
        return CryptoUtil.encryptWithAES(hashedVote, sessionKey);
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
