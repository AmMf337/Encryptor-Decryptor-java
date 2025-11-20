# Encryptor-Decryptor-java

Sistema robusto de cifrado de archivos implementado en Java que utiliza AES-256-CBC, derivación de claves PBKDF2 y verificación de integridad mediante SHA-256.

Vision general del programa:

```bash
┌─────────────────┐
│  Archivo .txt   │
│  (texto/texts/) │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│ 1. Leer archivo         │
│    byte[] fileData      │
└────────┬────────────────┘
         │
         ├──────────────────────┐
         │                      │
         ▼                      ▼
┌─────────────────┐    ┌──────────────────┐
│ 2. Calcular     │    │ 3. Generar SALT  │
│    SHA-256      │    │    (16 bytes)    │
│    del original │    └────────┬─────────┘
└────────┬────────┘             │
         │                      ▼
         │             ┌──────────────────┐
         │             │ 4. PBKDF2        │
         │             │    Password+Salt │
         │             │    65536 iter    │
         │             └────────┬─────────┘
         │                      │
         │                    KEY (32 bytes)
         │                      │
         │             ┌────────▼─────────┐
         │             │ 5. Generar IV    │
         │             │    (16 bytes)    │
         │             └────────┬─────────┘
         │                      │
         │             ┌────────▼─────────┐
         │             │ 6. Cifrar AES    │
         │             │    Modo CBC      │
         │             └────────┬─────────┘
         │                      │
         └──────┬───────────────┘
                │
        ┌───────▼────────────┐
        │ 7. Escribir .enc:  │
        │    [SALT]          │
        │    [IV]            │
        │    [HASH]          │
        │    [CIFRADO]       │
        └────────────────────┘
```

### Encriptado

Para el proceso de encriptado hay ciertas valores fijos declarados en el programa:

```java
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final int IV_SIZE = 16;
    private static final int SALT_SIZE = 16;
```

- **ALGORITHM**: Esta variable tiene el valor con el cual se genera la instancia de la clase **Cypher** para el cifrado del archivo. En este caso se usa del algoritmo **AES** en modelidad **CBC** y con padding **PKCS5**.
- **KEY_SIZE**: Tamaño de la llave generada por el algoritmo AES.
- **ITERATION_COUNT**: El número de iteraciones de la función **HMAC-SHA256** aplicada por el algoritmo PBKDF2. Esto ofrece mayor protección frente a ataques de fuerza bruta.
- **IV_SIZE**: El tamaño del vector de inicialización. Este permite que aunque se cifre el mismo mensaje el resultado sea totalmente diferente evitando ánalisis de reconocimiento de patrones.
- **SALT_SIZE**: El tamaño del salt. Este es el valor aleatorio con el cual se formara la clave de cifrado, esto permite que la llave de cifrado generada sea diferente incluso usando la misma contraseña.

```java
private static void encryptFile(Scanner scanner) throws Exception {
        System.out.print("Nombre del archivo a cifrar: ");
        String inputFile = ("./texts/" + scanner.nextLine() + ".txt");

        System.out.print("Nombre del archivo cifrado (salida): ");
        String outputFile = ("./encrypted/" + scanner.nextLine() + ".enc");

        System.out.print("Contraseña: ");
        String password = scanner.nextLine();

        byte[] fileData = readFile(inputFile);

        byte[] fileHash = calculateSHA256(fileData);
        System.out.println("Hash SHA-256 del archivo original: " + bytesToHex(fileHash));

        byte[] salt = generateRandomBytes(SALT_SIZE);

       
        SecretKey key = deriveKey(password, salt);

        
        byte[] iv = generateRandomBytes(IV_SIZE);

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
```
Los pasos del metodo son: 
 
 1. Lectura de ruta de archivo de origen y destino asi como de la contraseña ingresada:
 
```java
  System.out.print("Nombre del archivo a cifrar: ");
        String inputFile = ("./texts/" + scanner.nextLine() + ".txt");

        System.out.print("Nombre del archivo cifrado (salida): ");
        String outputFile = ("./encrypted/" + scanner.nextLine() + ".enc");

        System.out.print("Contraseña: ");
        String password = scanner.nextLine();

        byte[] fileData = readFile(inputFile);
```

2. Calculo del hash del archivo original:

```java
  byte[] fileHash = calculateSHA256(fileData);
        System.out.println("Hash SHA-256 del archivo original: " + bytesToHex(fileHash));
```

3. Generación del salt, llave cifrada y el vector de inicialización:

```java
        byte[] salt = generateRandomBytes(SALT_SIZE);
       
        SecretKey key = deriveKey(password, salt);
        
        byte[] iv = generateRandomBytes(IV_SIZE);
```

**Método deriveKey**:

```java
private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
```

Este método genera una instancia de la clase de generación de llaves **SecretKeyFactory** usando el algoritmo **PBKDF2WithHmacSHA256**, luego crea una clase de especificación para los parametros de la clave, genera la llave cifrada y la transforma al formato AES.

**Método encrypt**

```java
private static byte[] encrypt(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(data);
    }

```
Se genera la instancia de la de cifrado Chipher con la especificación de AES explicada anteriormente, se genera el vector de inicialización con el tamaño especificado y finalmente se encripta el mensaje con la instancia de cipher con los valores especificados.

4. Escribir y guardar datos cifrados en formato estandar:

```java
 byte[] encryptedData = encrypt(fileData, key, iv);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(fileHash);
            fos.write(encryptedData);
        }
```

Se escribe en el archivo de origen cada parte de encriptación en el orden especificado y los datos encriptados al final.

### Desencriptado

```java
    private static void decryptFile(Scanner scanner) throws Exception {
        System.out.print("Nombre del archivo cifrado: ");
        String inputFile = ("./encrypted/" + scanner.nextLine() + ".enc");

        System.out.print("Ruta del archivo descifrado (salida): ");
        String outputFile = ("./decrypted/" + scanner.nextLine() + ".txt");

        System.out.print("Contraseña: ");
        String password = scanner.nextLine();

        byte[] encryptedFile = readFile(inputFile);

        if (encryptedFile.length < SALT_SIZE + IV_SIZE + 32) {
            throw new Exception("Archivo cifrado inválido o corrupto");
        }

        byte[] salt = Arrays.copyOfRange(encryptedFile, 0, SALT_SIZE);
        byte[] iv = Arrays.copyOfRange(encryptedFile, SALT_SIZE, SALT_SIZE + IV_SIZE);
        byte[] storedHash = Arrays.copyOfRange(encryptedFile, SALT_SIZE + IV_SIZE,
                SALT_SIZE + IV_SIZE + 32);
        byte[] encryptedData = Arrays.copyOfRange(encryptedFile, SALT_SIZE + IV_SIZE + 32,
                encryptedFile.length);

        System.out.println("Hash SHA-256 almacenado: " + bytesToHex(storedHash));

        SecretKey key = deriveKey(password, salt);

        byte[] decryptedData = decrypt(encryptedData, key, iv);

        byte[] computedHash = calculateSHA256(decryptedData);
        System.out.println("Hash SHA-256 calculado: " + bytesToHex(computedHash));

        if (MessageDigest.isEqual(storedHash, computedHash)) {
            System.out.println("✓ Verificación de integridad exitosa");

           
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(decryptedData);
            }

            System.out.println("Archivo descifrado exitosamente: " + outputFile);
        } else {
            System.err.println("✗ ERROR: La verificación de integridad falló");
            System.err.println("El archivo puede estar corrupto o la contraseña es incorrecta");
        }
    }
```

