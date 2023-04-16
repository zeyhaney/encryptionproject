import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class RSA implements EncryptionAlgorithm {

    private static final String NAME = "RSA";
    private static final int KEY_SIZE = 2048;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSA() {
        generateKeyPair();
    }

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
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new EncryptionException("Error encrypting data with RSA", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] data, String key) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new EncryptionException("Error decrypting data with RSA", e);
        }
    }

    public String getPublicKeyAsString() {
        return Utils.encodeBase64(publicKey.getEncoded());
    }

    public String getPrivateKeyAsString() {
        return Utils.encodeBase64(privateKey.getEncoded());
    }

    public void setPublicKeyFromString(String publicKeyString) throws InvalidKeySpecException {
        try {
            byte[] publicKeyBytes = Utils.decodeBase64(publicKeyString);
            KeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Error setting public key from string", e);
        }
    }

    public void setPrivateKeyFromString(String privateKeyString) throws InvalidKeySpecException {
        try {
            byte[] privateKeyBytes = Utils.decodeBase64(privateKeyString);
            KeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Error setting private key from string", e);
        }
    }

    private void generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            // This should never happen, as RSA is a standard algorithm
            e.printStackTrace();
        }
    }

}