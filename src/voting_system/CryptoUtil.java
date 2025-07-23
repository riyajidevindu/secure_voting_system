package voting_system;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;

public class CryptoUtil {

    /* ========== AES Encryption/Decryption ========== */
    public static String encryptWithAES(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decryptWithAES(String ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        return new String(cipher.doFinal(decoded));
    }

    /* ========== RSA Encryption/Decryption ========== */
    public static String encryptWithRSA(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decryptWithRSA(String ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        return new String(cipher.doFinal(decoded));
    }

    /* ========== SHA-256 Hash ========== */
    public static String sha256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(digest.digest(input.getBytes()));
    }

    /* ========== Sign/Verify ========== */
    public static byte[] sign(String data, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data.getBytes());
        return sig.sign();
    }

    public static boolean verifySignature(String data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data.getBytes());
        return sig.verify(signatureBytes);
    }

    /* ========== Diffie-Hellman Key Derivation ========== */
    public static SecretKey deriveAESKey(BigInteger sharedSecret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] full = digest.digest(sharedSecret.toByteArray());
        byte[] keyBytes = new byte[16];
        System.arraycopy(full, 0, keyBytes, 0, 16);
        return new SecretKeySpec(keyBytes, "AES");
    }
}
