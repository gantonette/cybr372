package part4;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FileEncryptor {

    // setting up the logger
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    // creating a random number generator and a constant
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int COUNT = 1000;

    public static void main(String[] args) {
        try {
            // checking the operation mode
            if ("enc".equals(args[0])) {
                String algorithm = args[1];
                int keyLength = Integer.parseInt(args[2]);
                char[] password = args[3].toCharArray();
                String inputFile = args[4];
                String outputFile = args[5];
                // calling the encryption function
                enc(algorithm, keyLength, password, inputFile, outputFile);
            } else if ("dec".equals(args[0])) {
                char[] password = args[1].toCharArray();
                String inputFile = args[2];
                String outputFile = args[3];
                // calling the decryption function
                dec(password, inputFile, outputFile);
            } else if ("info".equals(args[0])) {
                String inputFile = args[1];
                // calling the info printing function
                printInfo(inputFile);
            } else {
                // unknown mode
                System.out.println("Unknown mode " + args[0]);
            }
        } catch (Exception e) {
            LOG.log(Level.INFO, "Unable to process", e);
        }
        LOG.info("Process complete");
    }

    /**
     * This method encrypts an input file using a specified algorithm, key length, and password.
     * Then it saves the encrypted file in the output directory.
     *
     * This method mainly performs:
     * 1. Cipher and key setup.
     * 2. Reading the input file and encrypting its contents.
     * 3. Writing algorithm info, IV length, IV, salt and encrypted input to the output file.
     * 4. Recording encryption metadata (key length and algorithm used) in the file attributes.
     *
     * @param algorithm The algorithm used for encryption in the format "algorithm/mode/padding".
     * @param keyLength The length of key used for encryption.
     * @param password  Password to be used for key derivation.
     * @param inputDir  Full path string of the input file to be encrypted.
     * @param outputDir Full path string of the output file to save after encryption.
     *
     * @throws Exception if any error occurs when setting up the cipher or encrypting the data.
     */
    public static void enc(String algorithm, int keyLength, char[] password, String inputDir, String outputDir)
            throws Exception {
        // setting up the encryption cipher
        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        RANDOM.nextBytes(iv);
        // generating salt for key derivation
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        IvParameterSpec ivv = new IvParameterSpec(iv);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, COUNT, keyLength);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
        SecretKeySpec key = new SecretKeySpec(pbeKey.getEncoded(), algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivv);
        // printing secret key for reference
        System.out.println("Secret key is " + new String(Base64.getEncoder().encode(key.getEncoded())));

        // encrypting the input file
        try (InputStream fin = Files.newInputStream(Paths.get(inputDir));
             FileOutputStream fout = new FileOutputStream(outputDir, false);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher)) {

            // writing algorithm info, IV length, IV, and salt
            byte[] algorithmBytes = algorithm.getBytes(StandardCharsets.UTF_8);
            fout.write(ByteBuffer.allocate(4).putInt(algorithmBytes.length).array());
            fout.write(algorithmBytes);
            fout.write(ByteBuffer.allocate(4).putInt(iv.length).array());
            fout.write(iv);
            fout.write(salt);

            // reading and encrypting file data
            final byte[] bytes = new byte[1024];
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }

            // writing encryption metadata to file attributes
            UserDefinedFileAttributeView userDefinedFAView = Files.getFileAttributeView(Paths.get(outputDir),
                    UserDefinedFileAttributeView.class);
            userDefinedFAView.write(Integer.toString(keyLength), Charset.defaultCharset().encode(keyLength + ""));
            userDefinedFAView.write(algorithm, Charset.defaultCharset().encode(algorithm));
        } catch (IOException e) {
            handleExceptions(e);
        }
        LOG.info("Encryption finished, saved at " + outputDir);
    }

    /**
     * This method decrypts the encrypted data for a given password, input directory, and output directory.
     *
     * @param password  The password in form of character array to decrypt the encrypted data.
     * @param inputDir  The directory where the encrypted data is stored.
     * @param outputDir The directory where the decrypted data will be stored.
     *
     * @throws Exception If an error occurs during the decryption process or if the
     * given array size read from the stream is less than 0.
     *
     * This method first reads the file metadata and retrieves the algorithm and IV.
     * then, it decrypts the key using the password and salt, and then it decrypts the data using
     * the key and IV.
     *
     * The decrypted data will be written to the specified output directory, and upon completion, a log
     * statement will be produced stating that the decryption process is complete.
     */
    public static void dec(char[] password, String inputDir, String outputDir) throws Exception {
        // decrypting process starts here
        byte[] iv;
        byte[] salt;
        String algorithm = null;
        int keyLength = 128;

        try (InputStream encryptedData = Files.newInputStream(Paths.get(inputDir))) {
            // reading metadata and getting algorithm and IV
            DataInputStream ds = new DataInputStream(encryptedData);
            int arraySize = ds.readInt();
            if (arraySize < 0) {
                throw new IllegalArgumentException("Invalid array size read from stream: " + arraySize);
            }
            byte[] algorithmBytes = new byte[arraySize];
            ds.readFully(algorithmBytes);
            algorithm = new String(algorithmBytes);
            int ivLength = ds.readInt();
            iv = new byte[ivLength];
            ds.readFully(iv);
            salt = new byte[16];
            ds.readFully(salt);

            // decrypting key using password and salt
            IvParameterSpec ivv = new IvParameterSpec(iv);
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, COUNT, keyLength);
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
            SecretKeySpec key = new SecretKeySpec(pbeKey.getEncoded(), algorithm);

            // decrypting using the key and IV
            Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, ivv);

            try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                 OutputStream decryptedOut = new FileOutputStream(outputDir)) {
                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptedOut.write(bytes, 0, length);
                }
            } catch (IOException e) {
                handleExceptions(e);
            }
        } catch (IOException ex) {
            // handling exceptions during decryption
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
        LOG.info("Decryption complete, open " + outputDir);
    }

    public static void printInfo(String inputFile) throws IOException {
        // printing algorithm and key length info
        try (DataInputStream ds = new DataInputStream(new FileInputStream(inputFile))) {
            byte[] algorithmnBytes = new byte[ds.readInt()];
            ds.readFully(algorithmnBytes);
            System.out.println("Algorithm: " + new String(algorithmnBytes));
            System.out.println("Key Length: " + ds.readInt());
        }
    }

    // simple function to handle exceptions and print messages
    public static void handleExceptions(Exception e) {
        System.out.println(e.getMessage());
    }
}
