import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;

public class KeyGenerator {

    // Generate a new encryption key with the specified key size
    public String generateKey(int keySize) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecureRandom random = new SecureRandom();
            keyGen.init(keySize, random);
            Key key = keyGen.generateKey();
            return javax.xml.bind.DatatypeConverter.printHexBinary(key.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    // Save the encryption key to a file
    public boolean saveKey(String key, String filename) {
        try {
            FileOutputStream fos = new FileOutputStream(filename);
            fos.write(key.getBytes());
            fos.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }
}