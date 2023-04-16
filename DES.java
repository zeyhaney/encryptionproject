import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class DES implements EncryptionAlgorithm {

    private static final String NAME = "DES";
    private static final int KEY_SIZE = 56;

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
            DESKeySpec desKeySpec = new DESKeySpec(key.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(desKeySpec);

            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new EncryptionException("Error encrypting data using DES", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] data, String key) throws EncryptionException {
        try {
            DESKeySpec desKeySpec = new DESKeySpec(key.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(desKeySpec);

            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new EncryptionException("Error decrypting data using DES", e);
        }
    }
}