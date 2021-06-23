import java.io.File;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Message implements Serializable {
    String filename;
    String caption;
    byte[] file;


    public Message(String filename, String caption, byte[] file) {
        this.filename = filename;
        this.caption = caption;
        this.file = file;
    }


    @Override
    public String toString() {
        return "Message{" +
                "filename='" + filename + '\'' +
                ", caption='" + caption + '\'' +
                ", file=" + Arrays.toString(file) +
                '}';
    }
}
