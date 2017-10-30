/*
  MIT License

  Copyright (c) 2016 Cian Butler

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.bind.DatatypeConverter;

class Key {
  Key(){}
  public byte [] get(byte [] pass) {
    byte [] salt = getSec("salt");
    byte[] salted = new byte[pass.length + salt.length];
    System.arraycopy(pass, 0, salted, 0, pass.length);
    System.arraycopy(salt, 0, salted, pass.length, salt.length);
    byte [] hashedKey = hash(salted);
    BigInteger encryptionKey = modPow(hashedKey);
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

  public byte [] getSec(String fileString) {
    String filePath = "./" + fileString + ".txt";
    try {
      Path file = Paths.get(filePath);
      Files.createFile(file);
      byte [] salt = new byte[16];
      SecureRandom random = new SecureRandom();
      random.nextBytes(salt);
      write(filePath, salt);
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

  private BigInteger modPow(byte [] key) {
    BigInteger modulus = readMod();
    if(modulus == BigInteger.ONE) return BigInteger.ZERO;
    BigInteger base = new BigInteger(key);
    BigInteger exponent = new BigInteger("65537");
    BigInteger c = BigInteger.ONE;
    String ex = exponent.toString(2);
    while(ex.length() > 0) {
      if ( ex.substring(ex.length() - 1, ex.length()).equals("1")) {
        c = c.multiply(base).mod(modulus);
      }
      base = base.multiply(base).mod(modulus);
      ex = ex.substring(0, ex.length() - 1);
    }
    write("./RSAPassword.txt", c.toByteArray());
    return c;
  }

  private void write (String fileName, byte [] key) {
    String data = DatatypeConverter.printHexBinary(key);
    try(PrintWriter out = new PrintWriter(fileName)){
      out.println(data);
    } catch(IOException e) {
      System.out.println(e.getMessage());
    }
  }

  private BigInteger readMod () {
    String filePath = "./Modulus";
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
      return new BigInteger(fileData.toString().replaceAll("\\s","").replaceAll("\\n", "").replaceAll("\\r", ""), 16);
    } catch(IOException e) {
      return null;
    }
  }
}

public class SymetricEncryptor {
  public static void main(final String[] args) throws Exception {
    String arg = args[0];
    if (arg != null && !arg.isEmpty()) {
      byte [] pass = getArg("Enter Password");
      Key key = new Key();
      if (arg.equals("-e")) {
        encrypt(args[1], key.get(pass));
        System.exit(0);
      }
      else if (arg.equals("-d")) {
        decrypt(args[1], args[2], key.get(pass));
        System.exit(0);
      }
    }
    System.out.println("Sorry no file specified");
    System.exit(1);
  }

  private static byte [] getArg(String msg) {
    Scanner scan = new Scanner(System.in);
    System.out.print(msg+ ": ");
    String s = scan.next();
    scan.close();
    return s.getBytes(Charset.forName("UTF-8"));
  }


  public static void encrypt(String file, byte [] key) {
    try {
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      byte [] iv = new Key().getSec("iv");
      IvParameterSpec ivspec = new IvParameterSpec(iv);
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivspec);
      Path path = Paths.get(file);
      byte[] message = Files.readAllBytes(path);
      byte[] encryptedMessage = cipher.doFinal(pad(message));
      System.out.println(DatatypeConverter.printHexBinary(encryptedMessage));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void decrypt (String in, String out, byte [] key) {
    try {
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      byte [] iv = new Key().getSec("iv");
      IvParameterSpec ivspec = new IvParameterSpec(iv);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivspec);
      Path path = Paths.get(in);
      byte[] message = DatatypeConverter.parseHexBinary(new String(Files.readAllBytes(path)).replaceAll("\\s","").replaceAll("\\n", "").replaceAll("\\r", ""));
      byte[] decryptedMessage = unpad(cipher.doFinal(message));
      System.out.println(out);
      Path secPath = Paths.get(out);
      Files.write(secPath, decryptedMessage);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static byte[] pad(byte[] message) {
    int paddingSize = message.length % 16 == 16
      ? 16
      : 16 - (message.length % 16);
    byte [] paddedMsg = new byte[message.length + paddingSize];
    System.arraycopy(message, 0, paddedMsg, 0, message.length);
    paddedMsg[message.length] = (byte) 0b10000000;
    return paddedMsg;
  }

  private static byte[] unpad(byte[] message) {
    int emptyBytes = 1;
    for(int i = message.length - 1; message[i] == 0; i--) {
      emptyBytes++;
    }
    byte[] result = new byte[message.length - emptyBytes];
    System.arraycopy(message, 0, result, 0, result.length);
    return result;
  }
}
