package part2;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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

public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE_IN_BYTES = 16;

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, IOException {
        // check if enough arguments are provided
        if (args.length < 4) {
            System.out.println("Insufficient arguments. Usage: 'mode key inputFile outputFile'");
            return;
        }
        // create a SecretKeySpec from the provided key
        SecretKeySpec skeySpec = new SecretKeySpec(Base64.getDecoder().decode(args[1]), ALGORITHM);

        // initialise the cipher
        Cipher cipher = Cipher.getInstance(CIPHER);

        // declare variables for file input/output
        Path outputPath;
        FileInputStream fis;
        FileOutputStream fos;
        byte[] ivBytes = new byte[IV_SIZE_IN_BYTES];

        // check if the operation is encryption or decryption
        if (args[0].equals("enc")) {
            // generate a random IV for encryption
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(ivBytes);

            // create an IvParameterSpec with the generated IV
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            // initialise the cipher for encryption
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

            // open input and output streams for file I/O
            fis = new FileInputStream(args[2]);
            outputPath = Paths.get(args[3]);
            fos = new FileOutputStream(outputPath.toFile());
            fos.write(ivBytes); // write the IV to the output file for decryption later

        } else { // decryption
            // read the iv from the encrypted file
            fis = new FileInputStream(args[2]);
            fis.read(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            // initialise the cipher for decryption
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);

            // set the output path for the decrypted file
            outputPath = Paths.get(args[3]);
            fos = new FileOutputStream(outputPath.toFile());
        }

        try {
            // initialise a CipherOutputStream to encrypt/decrypt and write data
            CipherOutputStream cipherOut = new CipherOutputStream(fos, cipher);

            // read and write file contents in chunks
            byte[] fileBytes = new byte[1024];
            int numRead;
            while ((numRead = fis.read(fileBytes)) >= 0) {
                cipherOut.write(fileBytes, 0, numRead);
            }

            cipherOut.close();
            fis.close();
        } catch (IOException e) {
            // handle exceptions related to file I/O
            LOG.log(Level.SEVERE, "File reading/writing failed", e);
        }

        LOG.info("Process complete, output saved at " + outputPath);
    }
}
