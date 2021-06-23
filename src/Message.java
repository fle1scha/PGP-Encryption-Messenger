import java.io.*;
import java.nio.file.Files;
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
        return "Message{" + "filename='" + filename + '\'' + ", caption='" + caption + '\'' + ", file="
                + Arrays.toString(file) + '}';
    }

    // Message to bytes
    public static byte[] messageToBytes(Message message) {
        byte[] data = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(message);
            oos.flush();
            data = bos.toByteArray();
            bos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return data;
    }

    // Message from bytes
    public static Message messageFromBytes(byte[] someBytes) {
        ByteArrayInputStream bis = new ByteArrayInputStream(someBytes);
        ObjectInput in = null;
        Message message = null;
        try {
            in = new ObjectInputStream(bis);
            Object o = in.readObject();
            message = (Message) o;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException ex) {
                // ignore close exception
            }
        }
        return message;
    }

    // Build message object
    public static Message buildMessage(String filepath, String caption) {

        File file = new File(filepath);
        byte[] bytes = new byte[0];
        try {
            bytes = Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new Message(file.getName(), caption, bytes);
    }
}
