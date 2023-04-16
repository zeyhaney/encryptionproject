import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyGenerator {
    private static final String ALGORITHM = "SHA1PRNG";

    public String generateKey(int keySize) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance(ALGORITHM);
        byte[] key = new byte[keySize / 8];
        secureRandom.nextBytes(key);
        return bytesToHex(key);
    }

    public boolean saveKey(String key, String filename) throws IOException {
        BufferedWriter writer = null;
        try {
            writer = new BufferedWriter(new FileWriter(filename));
            writer.write(key);
            return true;
        } finally {
            if (writer != null) {
                writer.close();
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
