package voting_system;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class Main {
    public static void main(String[] args) throws Exception {
        BigInteger g = BigInteger.valueOf(5);
        BigInteger p = BigInteger.probablePrime(256, new Random());

        Admin admin = new Admin(g, p);
        List<Voter> voters = List.of(
                new Voter("voter1", g, p),
                new Voter("voter2", g, p),
                new Voter("voter3", g, p)
        );

        for (Voter voter : voters) {
            admin.registerVoter(voter);
        }

        String[] candidates = {"Candidate A", "Candidate B", "Candidate C"};
        Random rand = new Random();

        for (Voter voter : voters) {
            System.out.println("\n===== Voting Session for: " + voter.voterID + " =====");

            if (admin.hasVoted(voter.voterID)) {
                System.out.println("ERROR: Voter already voted.");
                continue;
            }

            // Step 1: Voter -> Admin
            BigInteger RA = voter.generateNonce();
            voter.setLastRA(RA);
            Admin.DHChallenge challenge = admin.initiateHandshake(voter, RA);

            // Step 2 & 3: Voter processes challenge
            String encryptedVoterResponse = voter.respondToDHChallenge(challenge, admin.keyPair.getPublic());

            // Step 4: Admin finalizes session key
            SecretKey sessionKey = admin.finalizeSessionKey(encryptedVoterResponse);
            voter.sessionKey = sessionKey;

            System.out.println("Session key established securely for " + voter.voterID);

            // Step 5: Admin -> Voter
            String encryptedCandidateList = CryptoUtil.encryptWithAES(String.join(",", candidates), sessionKey);
            System.out.println("Encrypted Candidate List: " + encryptedCandidateList);

            // Step 6: Voter -> Admin
            String selected = candidates[rand.nextInt(candidates.length)];
            System.out.println("Voter selected: " + selected);
            String hashedVote = CryptoUtil.sha256(selected);
            String encryptedVote = CryptoUtil.encryptWithAES(hashedVote, sessionKey);

            // Step 7: Admin stores
            String receivedHash = CryptoUtil.decryptWithAES(encryptedVote, sessionKey);
            admin.storeVote(receivedHash);
            admin.markVoted(voter.voterID);

            System.out.println("Vote submitted securely.");
        }

        admin.tallyVotes(candidates);
    }
}
