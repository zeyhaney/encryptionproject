import javax.swing.*;
import java.awt.Component;
import java.io.File;

public class FileChooser {

    public static File chooseFile(Component parent) {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(parent);
        if (result == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();
        } else {
            return null;
        }
    }
}

