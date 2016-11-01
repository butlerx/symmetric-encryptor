import java.math.BigInteger;
import javax.crypto.*;
import java.security.*;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.*;
import java.util.*;

class Key {
  public void init() {
    String primeString =  readFile("./prime");
    String generatorString = readFile("./generator");
    String publicKeyString = readFile("./publicKey");
    BigInteger localPrivateKey = loadKey("./localPrivateKey");
    BigInteger prime = new BigInteger(primeString, 16);
    BigInteger generator = new BigInteger(generatorString, 16);
    BigInteger publicKey = new BigInteger(publicKeyString, 16);
    while (localPrivateKey.bitLength() != 1023) {
      Random rnd = new Random(System.currentTimeMillis());
      localPrivateKey = new BigInteger(1023, rnd);
    }
    writeKey("./localPrivateKey", localPrivateKey);
    BigInteger localPublicKey = modPow(generator, localPrivateKey, prime);

    System.out.println(localPrivateKey + " " + localPrivateKey.bitLength());
    System.out.println(localPublicKey + " " + localPublicKey.bitLength());
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
      System.out.println(e.getMessage());
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
      System.out.println(e.getMessage());
      String localPrivateKeyString = readFile("./localPrivateKey");
      BigInteger localPrivateKey = new BigInteger(localPrivateKeyString, 16);
      return localPrivateKey;
    }
  }

  private void writeKey (String fileName, BigInteger key) {
    try {
      List<String> lines = Arrays.asList(key.toString(16));
      Path file = Paths.get("localPrivateKey");
      Files.write(file, lines, Charset.forName("UTF-8"));
    } catch(IOException e) {
      System.out.println(e.getMessage());
    }
  }
}

public class SymetricEncryptor {
  public static void main(final String[] args) throws Exception {
    new Key().init();
  }
}
