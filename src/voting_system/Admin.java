package voting_system;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.*;
import java.util.*;

public class Admin {
    public final KeyPair keyPair;
    private final BigInteger p;   // DH modulus
    private final BigInteger g;   // DH base
    private BigInteger b;         // DH private
    public BigInteger g_b;        // DH public
    private final Map<String, Boolean> voterStatus = new HashMap<>();
    private final List<String> voteLedger = new ArrayList<>();

    private BigInteger lastRB;
    private BigInteger lastRA;
    private Voter currentVoter;

    public Admin(BigInteger g, BigInteger p) throws Exception {
        this.g = g;
        this.p = p;
        this.keyPair = generateRSAKeyPair();
        regenerateDH();
    }

    public void registerVoter(Voter voter) {
        voterStatus.put(voter.voterID, false);
    }

    public boolean hasVoted(String voterID) {
        return voterStatus.getOrDefault(voterID, false);
    }

    public void markVoted(String voterID) {
        voterStatus.put(voterID, true);
    }

    public DHChallenge initiateHandshake(Voter voter, BigInteger RA) throws Exception {
        System.out.println("Admin: Received hello from " + voter.voterID + " with RA = " + RA);
        this.currentVoter = voter;
        this.lastRA = RA;
        regenerateDH();

        this.lastRB = new BigInteger(128, new SecureRandom());
        String payload = RA + "|" + g_b;

        // Encrypt
        String encryptedPayload = CryptoUtil.encryptWithRSA(payload, voter.keyPair.getPublic());

        // Sign the encrypted payload
        byte[] signatureBytes = CryptoUtil.sign(encryptedPayload, keyPair.getPrivate());
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

        return new DHChallenge(lastRB, encryptedPayload, signatureBase64);
    }

    public SecretKey finalizeSessionKey(String encryptedVoterResponse) throws Exception {
        String[] parts = encryptedVoterResponse.split("::");
        String encryptedPayload = parts[0];
        String signatureBase64 = parts[1];

        // Verify signature first
        boolean valid = CryptoUtil.verifySignature(encryptedPayload,
                Base64.getDecoder().decode(signatureBase64),
                currentVoter.keyPair.getPublic());
        if (!valid) {
            throw new SecurityException("Voter signature invalid.");
        }

        // Decrypt
        String decrypted = CryptoUtil.decryptWithRSA(encryptedPayload, keyPair.getPrivate());
        String[] fields = decrypted.split("\\|");
        BigInteger receivedRB = new BigInteger(fields[0]);
        BigInteger voter_g_a = new BigInteger(fields[1]);

        if (!receivedRB.equals(this.lastRB)) {
            throw new SecurityException("RB does not match.");
        }

        BigInteger Ks = voter_g_a.modPow(this.b, p);
        return CryptoUtil.deriveAESKey(Ks);
    }

    public void storeVote(String hash) {
        voteLedger.add(hash);
    }

    public void tallyVotes(String[] candidates) throws Exception {
        System.out.println("===== Final Tally =====");
        Map<String, Integer> tally = new HashMap<>();
        for (String candidate : candidates) {
            String hash = CryptoUtil.sha256(candidate);
            long count = voteLedger.stream().filter(h -> h.equals(hash)).count();
            tally.put(candidate, (int) count);
        }
        tally.forEach((k, v) -> System.out.println(k + ": " + v + " vote(s)"));
    }

    private void regenerateDH() {
        this.b = new BigInteger(256, new SecureRandom());
        this.g_b = g.modPow(b, p);
    }

    private KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static class DHChallenge {
        public final BigInteger RB;
        public final String encryptedPayload;
        public final String signature;

        public DHChallenge(BigInteger RB, String encryptedPayload, String signature) {
            this.RB = RB;
            this.encryptedPayload = encryptedPayload;
            this.signature = signature;
        }
    }
}
