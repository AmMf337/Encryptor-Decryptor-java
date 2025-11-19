import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class Encryptor {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final int IV_SIZE = 16;
    private static final int SALT_SIZE = 16;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("=== Sistema de Cifrado de Archivos ===");
        System.out.println("1. Cifrar archivo");
        System.out.println("2. Descifrar archivo");
        System.out.print("Seleccione una opción: ");

        int option = scanner.nextInt();
        scanner.nextLine();

        try {
            if (option == 1) {
                encryptFile(scanner);
            } else if (option == 2) {
                decryptFile(scanner);
            } else {
                System.out.println("Opción inválida");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }

        scanner.close();
    }

    private static void encryptFile(Scanner scanner) throws Exception {
        System.out.print("Ruta del archivo a cifrar: ");
        String inputFile = scanner.nextLine();

        System.out.print("Ruta del archivo cifrado (salida): ");
        String outputFile = scanner.nextLine();

        System.out.print("Contraseña: ");
        String password = scanner.nextLine();

        // Leer archivo original
        byte[] fileData = readFile(inputFile);

        // Calcular hash SHA-256 del archivo original
        byte[] fileHash = calculateSHA256(fileData);
        System.out.println("Hash SHA-256 del archivo original: " + bytesToHex(fileHash));

        // Generar salt aleatorio
        byte[] salt = generateRandomBytes(SALT_SIZE);

        // Derivar clave usando PBKDF2
        SecretKey key = deriveKey(password, salt);

        // Generar IV aleatorio
        byte[] iv = generateRandomBytes(IV_SIZE);

        // Cifrar archivo
        byte[] encryptedData = encrypt(fileData, key, iv);

        // Escribir archivo cifrado con estructura:
        // [SALT(16)][IV(16)][HASH(32)][DATOS_CIFRADOS]
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(fileHash);
            fos.write(encryptedData);
        }

        System.out.println("Archivo cifrado exitosamente: " + outputFile);
    }

    private static void decryptFile(Scanner scanner) throws Exception {
        System.out.print("Ruta del archivo cifrado: ");
        String inputFile = scanner.nextLine();

        System.out.print("Ruta del archivo descifrado (salida): ");
        String outputFile = scanner.nextLine();

        System.out.print("Contraseña: ");
        String password = scanner.nextLine();

        // Leer archivo cifrado
        byte[] encryptedFile = readFile(inputFile);

        if (encryptedFile.length < SALT_SIZE + IV_SIZE + 32) {
            throw new Exception("Archivo cifrado inválido o corrupto");
        }

        // Extraer componentes
        byte[] salt = Arrays.copyOfRange(encryptedFile, 0, SALT_SIZE);
        byte[] iv = Arrays.copyOfRange(encryptedFile, SALT_SIZE, SALT_SIZE + IV_SIZE);
        byte[] storedHash = Arrays.copyOfRange(encryptedFile, SALT_SIZE + IV_SIZE,
                SALT_SIZE + IV_SIZE + 32);
        byte[] encryptedData = Arrays.copyOfRange(encryptedFile, SALT_SIZE + IV_SIZE + 32,
                encryptedFile.length);

        System.out.println("Hash SHA-256 almacenado: " + bytesToHex(storedHash));

        // Derivar clave usando PBKDF2
        SecretKey key = deriveKey(password, salt);

        // Descifrar datos
        byte[] decryptedData = decrypt(encryptedData, key, iv);

        // Calcular hash del archivo descifrado
        byte[] computedHash = calculateSHA256(decryptedData);
        System.out.println("Hash SHA-256 calculado: " + bytesToHex(computedHash));

        // Verificar integridad
        if (MessageDigest.isEqual(storedHash, computedHash)) {
            System.out.println("✓ Verificación de integridad exitosa");

            // Escribir archivo descifrado
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(decryptedData);
            }

            System.out.println("Archivo descifrado exitosamente: " + outputFile);
        } else {
            System.err.println("✗ ERROR: La verificación de integridad falló");
            System.err.println("El archivo puede estar corrupto o la contraseña es incorrecta");
        }
    }

    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private static byte[] encrypt(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(data);
    }

    private static byte[] calculateSHA256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    private static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static byte[] readFile(String filename) throws IOException {
        try (FileInputStream fis = new FileInputStream(filename);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            return baos.toByteArray();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}