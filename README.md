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
1. Lectura de rutas y contraseña:javaSystem.out.print("Nombre del archivo cifrado: ");

```java
String inputFile = ("./encrypted/" + scanner.nextLine() + ".enc");

System.out.print("Ruta del archivo descifrado (salida): ");
String outputFile = ("./decrypted/" + scanner.nextLine() + ".txt");

System.out.print("Contraseña: ");
String password = scanner.nextLine();

byte[] encryptedFile = readFile(inputFile);
```

2. Validación del tamaño del archivo:

```java
if (encryptedFile.length < SALT_SIZE + IV_SIZE + 32) {
    throw new Exception("Archivo cifrado inválido o corrupto");
}
```

3. Extracción de componentes del archivo cifrado:

```java
byte[] salt = Arrays.copyOfRange(encryptedFile, 0, SALT_SIZE);
byte[] iv = Arrays.copyOfRange(encryptedFile, SALT_SIZE, SALT_SIZE + IV_SIZE);
byte[] storedHash = Arrays.copyOfRange(encryptedFile, SALT_SIZE + IV_SIZE,
        SALT_SIZE + IV_SIZE + 32);
byte[] encryptedData = Arrays.copyOfRange(encryptedFile, SALT_SIZE + IV_SIZE + 32,
        encryptedFile.length);

System.out.println("Hash SHA-256 almacenado: " + bytesToHex(storedHash));
```
En este paso es importante que el formato en el que se guardó el archivo cifrado sea igual al esperado, pues si alguno de los valores no concuerda o esta en otra posición el desencriptado fallará.

4. Derivación de la clave usando PBKDF2:

```java
SecretKey key = deriveKey(password, salt);
```

**Método deriveKey**

```java
private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_SIZE);
    SecretKey tmp = factory.generateSecret(spec);
    return new SecretKeySpec(tmp.getEncoded(), "AES");
}
```
Se repite el proceso de generación de la clave con el salt extraido y la contraseña ingresada, si alguno de los valores es diferente el descifrado produce basura.

5. Desencriptado de los datos:

```java
javabyte[] decryptedData = decrypt(encryptedData, key, iv);
```

**Método decrypt**:

```java
private static byte[] decrypt(byte[] data, SecretKey key, byte[] iv) throws Exception {
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    return cipher.doFinal(data);
}
```

Se repite el proceso del método encrypt usando el la llave generada, el iv extraido y con la clase cipher en modo decrypt.

6. Cálculo del hash del archivo descifrado:

```java
byte[] computedHash = calculateSHA256(decryptedData);
System.out.println("Hash SHA-256 calculado: " + bytesToHex(computedHash));
.....
.....
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

```

## Dificultades

En el desarrollo del proyecto surgieron varias dificultades concretas relacionadas con el manejo de parámetros criptográficos. Una de las más frecuentes fue el uso incorrecto de valores como el tamaño del IV, el tamaño del salt o el número de iteraciones para PBKDF2. En algunos casos, cambiar uno de estos valores sin actualizar el resto provocaba que el descifrado generara datos ilegibles, haciendo difícil identificar el origen del problema. Otra dificultad se presentó al escribir y leer el archivo cifrado: si los bytes no se almacenaban exactamente en el orden definido (salt, IV, hash y datos cifrados), el descifrado fallaba aunque el algoritmo fuera correcto, lo que obligó a revisar cuidadosamente el formato y el manejo de índices en los arreglos.

También resultó desafiante interpretar errores silenciosos propios de la criptografía. Por ejemplo, cuando se usaba una contraseña incorrecta, un salt distinto o parámetros mal configurados, el programa no generaba una excepción clara, sino que producía resultados inválidos. Esto obligó a depurar con herramientas auxiliares, como impresión de hashes intermedios, para localizar el origen del problema. En resumen, el proyecto permitió comprender mejor la importancia del uso adecuado de parámetros criptográficos y la atención al detalle al manipular datos binarios dentro de un sistema de cifrado real.

## Conclusiones

Como conclusión, el proyecto permitió aplicar de manera práctica conceptos fundamentales de criptografía moderna dentro de un desarrollo real en Java. El uso de AES en modo CBC combinado con claves derivadas mediante PBKDF2 reforzó la seguridad del cifrado, haciendo más difícil que un atacante pueda obtener la clave mediante fuerza bruta. Además, la inclusión de un hash SHA-256 permitió validar la integridad del archivo descifrado, garantizando que no hubiera sido manipulado durante el proceso. En términos generales, la experiencia ayudó a comprender de forma concreta cómo funcionan los mecanismos de cifrado, derivación de claves y verificación de integridad, tal como se aplican en sistemas reales orientados a proteger la confidencialidad de la información.

Finalamente se calcula el hash del mensaje y se compara con el extraido, si son diferentes puede significar que el mensaje fue modificado o el archivo esta corrupto.
