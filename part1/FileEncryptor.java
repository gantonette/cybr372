package part1;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptor {

    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    // method to convert bytes to hexadecimal representation. I pasted it here instead because I was encountering issues
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        // check the number of arguments
        if (args.length < 3 || args.length > 5) {
            System.out.println("Usage: java FileEncryptor enc inputFile outputFile");
            System.out.println("or java FileEncryptor dec key iv inputFile outputFile");
            return;
        }

        // determine encryption or decryption mode and initialise variables
        String mode = args[0]; // enc or dec
        String inputFile;
        String outputFile;
        byte[] keyBytes;
        byte[] ivBytes = new byte[16];
        SecureRandom sr = new SecureRandom();

        // encryption mode
        if ("enc".equals(mode)) {
            inputFile = args[1];
            outputFile = args[2];
            keyBytes = new byte[16];
            sr.nextBytes(keyBytes);
            sr.nextBytes(ivBytes);

            //Print generated key and iv in both hex and base64 formats
            System.out.println("Generated Key (Hex): " + bytesToHex(keyBytes));
            System.out.println("Generated IV (Hex): " + bytesToHex(ivBytes));
            System.out.println("Generated Key (Base64): " + Base64.getEncoder().encodeToString(keyBytes));
            System.out.println("Generated IV (Base64): " + Base64.getEncoder().encodeToString(ivBytes));
        }
        // DECRYPTION mode
        else if ("dec".equals(mode)) {
            if(args.length < 5){
                System.out.println("For decryption, provide key and IV in base64.");
                return;
            }
            String key = args[1];
            String iv = args[2];
            inputFile = args[3];
            outputFile = args[4];
            keyBytes = Base64.getDecoder().decode(key);
            ivBytes = Base64.getDecoder().decode(iv);
        } else {
            System.out.println("Unknown mode " + mode + ". Must be 'enc' or 'dec'.");
            return;
        }

        // initialise cipher with the specified algorithm and mode
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init("enc".equals(mode) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, skeySpec, ivSpec);

        // process input and output streams for encryption/decryption
        Path outputPath = Paths.get(outputFile);
        try (
                InputStream in = Files.newInputStream(Paths.get(inputFile));
                OutputStream out = Files.newOutputStream(outputPath);
                CipherOutputStream cipherOut = new CipherOutputStream(out, cipher)
        ){
            byte[] bytes = new byte[1024];
            for(int length = in.read(bytes); length != -1; length = in.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to process", e);
        }

        LOG.info("Process complete, output saved at " + outputFile);
    }
}
