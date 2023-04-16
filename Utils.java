import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Utils {

    public static byte[] readBytesFromFile(File file) throws IOException {
        Path filePath = Paths.get(file.getAbsolutePath());
        return Files.readAllBytes(filePath);
    }

    public static void writeBytesToFile(File file, byte[] data) throws IOException {
        Path filePath = Paths.get(file.getAbsolutePath());
        Files.write(filePath, data);
    }
}