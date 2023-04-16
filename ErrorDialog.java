import javax.swing.*;

public class ErrorDialog {
    private final JDialog dialog;

    public ErrorDialog(Component parent, String title, String message) {
        // Create a new dialog with the specified title and message
        dialog = new JDialog(SwingUtilities.getWindowAncestor(parent), title, Dialog.ModalityType.APPLICATION_MODAL);

        // Create a label to display the error message
        JLabel label = new JLabel(message);

        // Add the label to the dialog
        dialog.getContentPane().add(label);

        // Add a close button to the dialog
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(closeButton);
        dialog.getContentPane().add(buttonPanel, "South");

        // Set the size and position of the dialog
        dialog.pack();
        dialog.setLocationRelativeTo(parent);
    }

    public void showDialog() {
        // Display the dialog to the user
        dialog.setVisible(true);
    }
}
