import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public class FileEncryptionGUI extends JFrame implements ActionListener {

    private JLabel labelFile;
    private JButton buttonChooseFile;
    private JRadioButton radioButtonAES, radioButtonDES, radioButtonRSA;
    private JPasswordField passwordField;
    private JButton buttonEncrypt, buttonDecrypt;

    private File selectedFile;

    public FileEncryptionGUI() {
        super("File Encryption and Decryption");

        initGUI();

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(400, 250);
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void initGUI() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1;
        constraints.insets = new Insets(5, 5, 5, 5);

        // File selection
        labelFile = new JLabel("No file selected");
        buttonChooseFile = new JButton("Choose File");
        buttonChooseFile.addActionListener(this);
        constraints.gridx = 0;
        constraints.gridy = 0;
        panel.add(labelFile, constraints);
        constraints.gridx = 1;
        panel.add(buttonChooseFile, constraints);

        // Encryption algorithm selection
        JLabel labelAlgorithm = new JLabel("Encryption Algorithm:");
        radioButtonAES = new JRadioButton("AES", true);
        radioButtonDES = new JRadioButton("DES");
        radioButtonRSA = new JRadioButton("RSA");
        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(radioButtonAES);
        buttonGroup.add(radioButtonDES);
        buttonGroup.add(radioButtonRSA);
        constraints.gridx = 0;
        constraints.gridy = 1;
        panel.add(labelAlgorithm, constraints);
        constraints.gridx = 1;
        panel.add(radioButtonAES, constraints);
        constraints.gridy = 2;
        panel.add(radioButtonDES, constraints);
        constraints.gridy = 3;
        panel.add(radioButtonRSA, constraints);

        // Password input
        JLabel labelPassword = new JLabel("Password:");
        passwordField = new JPasswordField();
        constraints.gridx = 0;
        constraints.gridy = 4;
        panel.add(labelPassword, constraints);
        constraints.gridx = 1;
        panel.add(passwordField, constraints);

        // Encrypt and Decrypt buttons
        buttonEncrypt = new JButton("Encrypt");
        buttonEncrypt.addActionListener(this);
        buttonDecrypt = new JButton("Decrypt");
        buttonDecrypt.addActionListener(this);
        constraints.gridx = 0;
        constraints.gridy = 5;
        panel.add(buttonEncrypt, constraints);
        constraints.gridx = 1;
        panel.add(buttonDecrypt, constraints);

        // Add the panel to the frame
        getContentPane().add(panel);
    }

    private void encryptFile() {
        if (selectedFile == null) {
            showErrorDialog("Please select a file to encrypt.");
            return;
        }

        String algorithmName = "";
        if (radioButtonAES.isSelected()) {
            algorithmName = "AES";
        } else if (radioButtonDES.isSelected()) {
            algorithmName = "DES";
        } else if (radioButtonRSA.isSelected()) {
            algorithmName = "RSA";
        }

        String password = new String(passwordField.getPassword());

        try {
            EncryptionAlgorithm algorithm = EncryptionAlgorithmFactory.getAlgorithm(algorithmName);
            String key = KeyGenerator.generateKey(algorithm.getKeySize(), password);
            byte[] fileContents = Utils.readBytesFromFile(selectedFile);
            byte[] encryptedContents = algorithm.encrypt(fileContents, key);
            File encryptedFile = new File(selectedFile.getPath() + ".encrypted");
            Utils.writeBytesToFile(encryptedFile, encryptedContents);
            showMessageDialog("Encryption completed successfully. The encrypted file is located at:\n" + encryptedFile.getPath());
        } catch (EncryptionException e) {
            showErrorDialog("Encryption failed: " + e.getMessage());
        }
    }

    private void decryptFile() {
        if (selectedFile == null) {
            showErrorDialog("Please select a file to decrypt.");
            return;
        }

        if (!selectedFile.getName().endsWith(".encrypted")) {
            showErrorDialog("Selected file is not an encrypted file.");
            return;
        }

        String algorithmName = "";
        if (radioButtonAES.isSelected()) {
            algorithmName = "AES";
        } else if (radioButtonDES.isSelected()) {
            algorithmName = "DES";
        } else if (radioButtonRSA.isSelected()) {
            algorithmName = "RSA";
        }

        String password = new String(passwordField.getPassword());

        try {
            EncryptionAlgorithm algorithm = EncryptionAlgorithmFactory.getAlgorithm(algorithmName);
            String key = KeyGenerator.generateKey(algorithm.getKeySize(), password);
            byte[] fileContents = Utils.readBytesFromFile(selectedFile);
            byte[] decryptedContents = algorithm.decrypt(fileContents, key);
            File decryptedFile = new File(selectedFile.getPath().replace(".encrypted", ""));
            Utils.writeBytesToFile(decryptedFile, decryptedContents);
            showMessageDialog("Decryption completed successfully. The decrypted file is located at:\n" + decryptedFile.getPath());
        } catch (EncryptionException e) {
            showErrorDialog("Decryption failed: " + e.getMessage());
        }
    }

    private void showMessageDialog(String message) {
        JOptionPane.showMessageDialog(this, message, "Information", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showErrorDialog(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == buttonChooseFile) {
            JFileChooser fileChooser = new JFileChooser();
            int result = fileChooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                selectedFile = fileChooser.getSelectedFile();
                labelFile.setText(selectedFile.getName());
            }
        } else if (e.getSource() == buttonEncrypt) {
            encryptFile();
        } else if (e.getSource() == buttonDecrypt) {
            decryptFile();
        }
    }
}