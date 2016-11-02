import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.*;
import java.util.*;

class Key {
  public byte [] init() {
    String primeString =  readFile("./prime");
    String generatorString = readFile("./generator");
    String publicKeyString = readFile("./publicKey");

    BigInteger localPrivateKey = loadKey("./localPrivateKey");
    BigInteger localPublicKey = loadKey("./localPublicKey");
    BigInteger sharedKey = loadKey("./sharedKey");

    BigInteger prime = new BigInteger(primeString, 16);
    BigInteger generator = new BigInteger(generatorString, 16);
    BigInteger publicKey = new BigInteger(publicKeyString, 16);
    while (localPrivateKey.bitLength() != 1023) {
      Random rnd = new Random(System.currentTimeMillis());
      localPrivateKey = new BigInteger(1023, rnd);
    }
    localPublicKey = modPow(generator, localPrivateKey, prime);
    sharedKey = modPow(publicKey, localPrivateKey, prime);

    writeKey("./localPrivateKey", localPrivateKey);
    writeKey("./localPublicKey", localPublicKey);
    writeKey("./sharedKey", sharedKey);

    byte [] hashedKey = hash(sharedKey);
    return hashedKey;
  }

  private BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {
    if(modulus == BigInteger.ONE) return BigInteger.ZERO;
    BigInteger c = BigInteger.ONE;
    String ex = exponent.toString(2);
    while(ex.length() > 0) {
      if ( ex.substring(ex.length()-1, ex.length()).equals("1")) {
        c = c.multiply(base).mod(modulus);
      }
      base = base.multiply(base).mod(modulus);
      ex = ex.substring(0,ex.length()-1);
    }
    return c;
  }

  private byte [] hash (BigInteger bi) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      String hash = bi.toString(16);
      md.update(hash.getBytes());
      byte [] digest = md.digest();
      return digest;
    } catch (Exception e) {
        return null;
    }
  }

  private String readFile (String filePath) {
    try {
      StringBuffer fileData = new StringBuffer();
      BufferedReader reader = new BufferedReader(new FileReader(filePath));
      char[] buf = new char[1024];
      int numRead=0;
      while((numRead=reader.read(buf)) != -1){
        String readData = String.valueOf(buf, 0, numRead);
        fileData.append(readData);
      }
      reader.close();
      return fileData.toString().replace("\n", "").replace("\r", "");
    } catch(IOException e) {
      return null;
    }
  }

  private BigInteger loadKey (String filePath) {
    try {
      Path file = Paths.get(filePath);
      Files.createFile(file);
      BigInteger c = BigInteger.ZERO;
      return c;
    } catch(IOException e) {
      String localPrivateKeyString = readFile(filePath);
      BigInteger localPrivateKey = new BigInteger(localPrivateKeyString, 16);
      return localPrivateKey;
    }
  }

  private void writeKey (String fileName, BigInteger key) {
    try {
      List<String> lines = Arrays.asList(key.toString(16));
      Path file = Paths.get(fileName);
      Files.write(file, lines, Charset.forName("UTF-8"));
    } catch(IOException e) {
      System.out.println(e.getMessage());
    }
  }
}

public class SymetricEncryptor {
  public static void main(final String[] args) throws Exception {
    String flag = args[0];
    if ( flag.equals("encrypt")) {
      byte [] key = new Key().init();
      encrypt(args[1], key);
    } else {
      if ( flag.equals("decrypt")) {
        byte [] key = new Key().init();
        decrypt(args[1], key);
      } else {
      System.out.println("Sorry thats not one of my arguments use either encrypt or decrypt filename");
      }
    }
  }

  public static void encrypt(String file, byte [] key) {
    try {
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      Cipher cipher  = Cipher.getInstance("AES");
      cipher.init(Cipher.ENCRYPT_MODE, keySpec);
      Path path = Paths.get(file);
      byte[] message = Files.readAllBytes(path);
      if (message.length % 16 != 0 ) {
        byte [] padding = new byte[message.length + (message.length%16)];
        for (int i = 0; i<message.length; i++) {
          padding[i] = message[i];
        }
        padding[message.length+1] = 1;
      }
      byte[] encryptedMessage = cipher.doFinal(message);
      Path secPath = Paths.get("sec-" + file);
      Files.write(secPath, encryptedMessage);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void decrypt (String file, byte [] key) {
    try {
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      Cipher cipher  = Cipher.getInstance("AES");
      cipher.init(Cipher.DECRYPT_MODE, keySpec);
      Path path = Paths.get(file);
      byte[] message = Files.readAllBytes(path);
      byte[] decryptedMessage = cipher.doFinal(message);
      Path secPath = Paths.get("unsec-" + file);
      Files.write(secPath, decryptedMessage);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
