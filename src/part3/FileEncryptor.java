package part3;

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
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class FileEncryptor {

    // set up a logger to record things
    private static final Logger LOG = Logger.getLogger(part3.FileEncryptor.class.getSimpleName());

    // declare some constants for the algorithm and cipher mode
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";


    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {

        // check if we have enough arguments for encryption mode
        if ((args.length < 4 || args.length > 5) && "enc".equals(args[0])) {
            System.out.println("Usage: java FileEncryptor enc password inputFile outputFile");
            return;
        }

        // check if we have enough arguments for decryption mode
        if ((args.length < 3 || args.length > 5) && "dec".equals(args[0])) {
            System.out.println("Usage: java FileEncryptor dec key iv inputFile outputFile");
            return;
        }

        // grab the encryption/decryption mode
        String mode = args[0]; // enc or dec
        String inputFile;
        String outputFile;
        byte[] keyBytes;
        byte[] ivBytes = new byte[16];
        SecureRandom sr = new SecureRandom();

        // If we're encrypting
        if ("enc".equals(mode)) {
            inputFile = args[2];
            outputFile = args[3];
            char[] password = args[1].toCharArray();
            byte[] salt = new byte[16];
            sr.nextBytes(salt);
            sr.nextBytes(ivBytes);
            System.out.println("Generated Salt: " + Base64.getEncoder().encodeToString(salt));

            // set up the key
            PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            keyBytes = skf.generateSecret(spec).getEncoded();
            sr.nextBytes(ivBytes);
            System.out.println("Generated Key: " + Base64.getEncoder().encodeToString(keyBytes));
            System.out.println("Generated IV: " + Base64.getEncoder().encodeToString(ivBytes));

            // save the salt and IV to their own files
            Files.write(Paths.get("salt.enc"), salt); // save the salt
            Files.write(Paths.get("iv.enc"), ivBytes); // save the IV

        }
        // If we're decrypting
        else if ("dec".equals(mode)) {
            char[] password = args[1].toCharArray();

            // grab the saved salt and IV
            byte[] salt = Files.readAllBytes(Paths.get("salt.enc"));
            ivBytes = Files.readAllBytes(Paths.get("iv.enc"));

            inputFile = args[2];
            outputFile = args[3];

            // set up the key again
            PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            keyBytes = skf.generateSecret(spec).getEncoded();
            System.out.println("Recovered Key: " + Base64.getEncoder().encodeToString(keyBytes));
        } else {
            // unknown mode, print issue to console
            System.out.println("Unknown mode " + mode + ". Must be 'enc' or 'dec'.");
            return;
        }

        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);

        // setting up the cipher depending on whether its encryption or decryption
        cipher.init("enc".equals(mode) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, skeySpec, ivSpec);

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
