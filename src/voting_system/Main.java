package voting_system;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class Main {
    // Helper method for formatted printing
    private static void printSection(String title) {
        System.out.println();
        System.out.println("------------------------------");
        System.out.println(title);
        System.out.println("------------------------------");
    }

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
            printSection("Voting Session for: " + voter.voterID);
            System.out.println();

            if (admin.hasVoted(voter.voterID)) {
                System.out.println();
                System.out.println("[ERROR] Voter '" + voter.voterID + "' has already voted. Skipping...\n");
                System.out.println();
                continue;
            }

            // Step 1: Voter -> Admin
            System.out.println();
            System.out.println("Step 1: Voter -> Admin (Nonce Generation)");
            BigInteger RA = voter.generateNonce();
            voter.setLastRA(RA);
            Admin.DHChallenge challenge = admin.initiateHandshake(voter, RA);

            // Step 2 & 3: Voter processes challenge
            System.out.println();
            System.out.println("Step 2 & 3: Voter processes challenge");
            String encryptedVoterResponse = voter.respondToDHChallenge(challenge, admin.keyPair.getPublic());

            // Step 4: Admin finalizes session key
            System.out.println();
            System.out.println("Step 4: Admin finalizes session key");
            SecretKey sessionKey = admin.finalizeSessionKey(encryptedVoterResponse);
            voter.sessionKey = sessionKey;
            System.out.println("[INFO] Session key established securely for '" + voter.voterID + "'.\n");
            System.out.println();

            // Step 5: Admin -> Voter
            System.out.println();
            System.out.println("Step 5: Admin -> Voter (Send Candidate List)");
            String encryptedCandidateList = admin.sendCandidateList(sessionKey, candidates);
            System.out.println("[ADMIN] Encrypted Candidate List: " + encryptedCandidateList + "\n");
            System.out.println();

            // Step 6: Voter -> Admin
            System.out.println();
            System.out.println("Step 6: Voter -> Admin (Send Encrypted Vote)");
            String encryptedVote = voter.prepareEncryptedVote(encryptedCandidateList);
            System.out.println("[" + voter.voterID + "] Encrypted Vote: " + encryptedVote + "\n");
            System.out.println();

            // Step 7: Admin stores
            System.out.println();
            System.out.println("Step 7: Admin stores the vote");
            admin.receiveEncryptedVote(sessionKey, encryptedVote, voter.voterID);
            System.out.println("[INFO] Vote submitted securely for '" + voter.voterID + "'.\n");
            System.out.println();
        }

        admin.tallyVotes(candidates);
        System.out.println();
        printSection("Final Tally");
        admin.tallyVotes(candidates);
    }
}
