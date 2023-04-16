import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

public class AES implements EncryptionAlgorithm {

    private static final String NAME = "AES";
    private static final int KEY_SIZE = 128;

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public int getKeySize() {
        return KEY_SIZE;
    }

    @Override
    public byte[] encrypt(byte[] data, String key) throws EncryptionException {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new EncryptionException("Error encrypting data with AES algorithm", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] data, String key) throws EncryptionException {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new EncryptionException("Error decrypting data with AES algorithm", ex);
        }
    }

}