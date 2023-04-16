public abstract class EncryptionAlgorithm {
    protected String name;
    protected int keySize;

    public String getName() {
        return name;
    }

    public int getKeySize() {
        return keySize;
    }

    public abstract byte[] encrypt(byte[] data, String key) throws EncryptionException;

    public abstract byte[] decrypt(byte[] data, String key) throws EncryptionException;
}