import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

public class InsecureEncryption {
    public static void main(String[] args) {
        // Set Bouncy Castle as security provider
        Security.addProvider(new BouncyCastleProvider());

        // Input for encryption
        String input = "Hello World!";
        System.out.println("Input : " + input);

        try {
            // Creating a cipher object for encryption
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");

            // ❌ INSECURE: random byte generation with Math.random()
            byte[] keyBytes = new byte[32]; // 256 Bit
            for (int i = 0; i < keyBytes.length; i++) {
                keyBytes[i] = (byte) (Math.random() * 256);
            }

            // Creating a secret key
            SecretKey key = new SecretKeySpec(keyBytes, "AES");

            // Initializing the cipher object
            cipher.init(Cipher.ENCRYPT_MODE, key);

            // Final encryption
            byte[] output = cipher.doFinal(input.getBytes());

            // Output of encryption
            System.out.println("Encrypted: " + Hex.toHexString(output));

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
