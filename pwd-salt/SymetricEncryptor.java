import java.io.*;
import java.math.BigInteger;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.bind.DatatypeConverter;

class IV {

  IV(){}

  public byte [] get() {
    String filePath = "./iv";
    File fs = new File();
    try {
      Path file = Paths.get(filePath);
      Files.createFile(file);
      byte [] iv = new byte[16];
      SecureRandom random = new SecureRandom();
      random.nextBytes(iv);
      fs.write(filePath, iv);
      return iv;
    } catch(IOException err) {
      byte[] iv = new byte[16];
      try(FileInputStream fis = new FileInputStream(filePath)){
        fis.read(iv);
      } catch(IOException e) {
        System.out.println(e.getMessage());
      }
      return iv;
    }
  }
}

class Key {
  Key(){}
  public byte [] get(byte [] pass) {
    byte [] salt = getSalt();
    byte[] salted = new byte[pass.length + salt.length];
    System.arraycopy(pass, 0, salted, 0, pass.length);
    System.arraycopy(salt, 0, salted, pass.length, salt.length);
    File fs = new File();
    BigInteger mod = new BigInteger(fs.read("./Modulus"), 16);
    byte [] hashedKey = hash(salted);
    BigInteger encryptionKey = modPow(new BigInteger(hashedKey), new BigInteger("65537"), mod);
    return hashedKey;
  }

  private byte [] hash (byte [] digest) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      for (int i = 0; i < 199; i++) {
        digest = md.digest(digest);
      }
      return digest;
    } catch (Exception e) {
      return null;
    }
  }

  private byte [] getSalt() {
    String filePath = "./salt";
    try {
      Path file = Paths.get(filePath);
      Files.createFile(file);
      byte [] salt = new byte[16];
      SecureRandom random = new SecureRandom();
      random.nextBytes(salt);
      File fs = new File();
      fs.write(filePath, salt);
      return salt;
    } catch(IOException err) {
      byte[] salt = new byte[16];
      try(FileInputStream fis = new FileInputStream(filePath)){
        fis.read(salt);
      } catch(IOException e) {
        System.out.println(e.getMessage());
      }
      return salt;
    }
  }

  private BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {
    if(modulus == BigInteger.ONE) return BigInteger.ZERO;
    BigInteger c = BigInteger.ONE;
    String ex = exponent.toString(2);
    while(ex.length() > 0) {
      if ( ex.substring(ex.length() - 1, ex.length()).equals("1")) {
        c = c.multiply(base).mod(modulus);
      }
      base = base.multiply(base).mod(modulus);
      ex = ex.substring(0, ex.length() - 1);
    }
    new File().write("./pass", c.toByteArray());
    return c;
  }
}

class File {

  File(){}

  public String read (String filePath) {
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
      return fileData.toString().replaceAll("\\s","").replaceAll("\\n", "").replaceAll("\\r", "");
    } catch(IOException e) {
      return null;
    }
  }

  public void write (String fileName, byte [] key) {
    String data = DatatypeConverter.printHexBinary(key);
    try(PrintWriter out = new PrintWriter(fileName)){
      out.println(data);
    } catch(IOException e) {
      System.out.println(e.getMessage());
    }
  }
}

public class SymetricEncryptor {
  public static void main(final String[] args) throws Exception {
    String flag = args[0];
    if ( flag.equals("-e")) {
      byte [] pass = getPwd();
      Key key = new Key();
      encrypt(args[1], key.get(pass));
    } else {
      if ( flag.equals("-d")) {
        byte [] pass = getPwd();
        Key key = new Key();
        decrypt(args[1], key.get(pass));
      } else {
        System.out.println("Sorry thats not one of my arguments use either -e (encrypt) or -d (decrypt) <filename>");
      }
    }
  }

  public static byte [] getPwd() {
    Scanner scan = new Scanner(System.in);
    System.out.print("Enter password: ");
    String s = scan.next();
    scan.close();
    return s.getBytes(Charset.forName("UTF-8"));
  }

  public static void encrypt(String file, byte [] key) {
    try {
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      byte [] iv = new IV().get();
      IvParameterSpec ivspec = new IvParameterSpec(iv);
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivspec);
      Path path = Paths.get(file);
      byte[] message = Files.readAllBytes(path);
      int paddingSize = message.length%16 == 0 ? 16 : message.length%16;
      byte [] paddedMsg = new byte[message.length + paddingSize];
      if (message.length % 16 != 0 ) {
        for (int i = 0; i < message.length; i++) {
          paddedMsg[i] = message[i];
        }
        paddedMsg[message.length+1] = 1;
      }
      byte[] encryptedMessage = cipher.doFinal(paddedMsg);
      System.out.println(file + ".sec");
      Path secPath = Paths.get(file + ".sec");
      Files.write(secPath, encryptedMessage);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void decrypt (String file, byte [] key) {
    try {
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      byte [] iv = new IV().get();
      IvParameterSpec ivspec = new IvParameterSpec(iv);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivspec);
      Path path = Paths.get(file);
      byte[] message = Files.readAllBytes(path);
      byte[] decryptedMessage = cipher.doFinal(message);
      file = file.substring(0, file.lastIndexOf('.'));
      System.out.println(file);
      Path secPath = Paths.get(file);
      Files.write(secPath, decryptedMessage);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
