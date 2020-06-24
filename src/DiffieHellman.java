/*
 *                             FileTrans 1.0                        
 *             Copyright © 2017 Ben Goldsworthy (rumperuu)        
 *                                                                      
 * A program to securely receive a file.
 *                                                                           
 * This file is part of FileTrans.                                         
 *                                                                            
 * FileTrans is free software: you can redistribute it and/or modify        
 * it under the terms of the GNU General Public License as published by       
 * the Free Software Foundation, either version 3 of the License, or          
 * (at your option) any later version.                                        
 *                                                                            
 * FileTrans is distributed in the hope that it will be useful,             
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              
 * GNU General Public License for more details.                               
 *                                                                            
 * You should have received a copy of the GNU General Public License          
 * along with FileTrans.  If not, see <http://www.gnu.org/licenses/>.       
 */

/**
 ** This class represents a client program for interfacing with an
 ** already-running instance of the server program.
 **/

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.regex.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 **   @author  Ben Goldsworthy (rumperuu) <me+filetrans@bengoldsworthy.net>
 **   @version 1.0
 **/
public class DiffieHellman {
   private static String ip = "";
   private static int port = 0;
   private static BigInteger p = null, g = null;
   private static int a = 0;
   
   /**
    **   Main function. Receives and validates arguments, then actives
    **   cracker threads.
    **   
    **   @param args The arguments passed to the program at the
    **   command-line.
    **/
	public static void main(String[] args) {
      // Quits with error if insufficent number of arguments passed at
      // command-line.
		if (args.length == 5) {
         parseArgs(args);
         
         try {
            // Connects to the server and sets up I/O.
            InetAddress addr = InetAddress.getByName(ip);
            Socket socket = new Socket(addr, port);
            System.out.println("Socket: " + socket);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())),true);
           
            // Performs the Diffie-Hellman key exchange protocol with the
            // server.
            out.println("##DHA##" + (g.pow(a).mod(p)) + "####");
            String B = parseResp(in.readLine());
            BigInteger s = new BigInteger(B).pow(a).mod(p);
            System.out.println("Shared Diffie-Hellman key: " + s);
            
            // Generates a nonce...
            String R = Double.toString(Math.floor(Math.random() * 9000 + 1000)).replaceAll(".0", "");
            // ...converts the D-H shared key into the hash string...
            String DH = s.toString();
            String DHKey = "";
            for (int i = 0; i < (12 - DH.length()); i++) { DHKey = DHKey + "0"; }
            String nonce = R + DHKey + DH;
            System.out.println("RDH: "+nonce);
            // ...and generates the 128-bit session key by hashing the
            // hash string and truncating it to the first 16 bytes.
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] sessionKey = digest.digest(nonce.getBytes("UTF-8"));
            sessionKey = Arrays.copyOfRange(sessionKey, 0, sessionKey.length/2);
            // Finally, sends nonce to the server.
            out.println("##NONCE##"+R+"####");
            
            // Requests the file from the server...
            out.println("##REQFILE####");
            String encodedFile = parseResp(in.readLine());
            System.out.println("File received: " +encodedFile);
            // ...decodes it from Base64...
            byte[] decodedFile = Base64.getDecoder().decode(encodedFile);
            // ...and decrypts it.
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            SecretKeySpec key = new SecretKeySpec(sessionKey, "AES");
            IvParameterSpec iv = new IvParameterSpec(nonce.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            String decryptedFile = new String(cipher.doFinal(decodedFile));//.substring(10);
            
            // Computes the hash of the file content...
            byte[] fileHash = digest.digest(decryptedFile.split(":", 2)[1].getBytes());
            // ...encrypts the hash with the session key...
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encryptedHash = cipher.doFinal(fileHash);
            // ...and returns it to the server for verification.
            String encodedHash = Base64.getEncoder().encodeToString(encryptedHash);
            System.out.println("Verifying hash: " + encodedHash);
            out.println("##VERIFY##"+encodedHash+"####");
            System.out.println(in.readLine());
            
            System.out.println(decryptedFile);
            
            socket.close();
         } catch (java.io.IOException e) {
            System.out.println("Can't connect to " + args[0]);
            System.out.println(e);
         } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
         } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
         } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
         } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
         } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
         }
      } else {
         System.out.println("Invalid number of arguments. Program should be run with the following arguments:");
         System.out.println("\tdh.jar <ip> <port> <p> <g> <secret number>");
         System.exit(1);
      }
	}
   
   /**
    **   Parses the arguments passed to the program to ensure they are
    **   valid.
    **/
   private static void parseArgs(String[] args) {
      ip = args[0];
         
      if (!isIP(ip)) {
         System.err.println("Invalid format of argument "+ip+": argument must be an IP address.");
         System.exit(1);
      } 
      
      ip = args[0];
      try {
         port = Integer.parseInt(args[1]);
         p = new BigInteger(args[2]);
         g = new BigInteger(args[3]);
         a = Integer.parseInt(args[4]);
      } catch (NumberFormatException e) {
         System.err.println("Invalid format of argument: argument must be an integer.");
         System.exit(1);
      }
   }
   
   /**
    **   Tests that the passed IP address is of a valid format.
    **/
   private static boolean isIP(String ip) {
      // Source for IP address RegEx: https://www.mkyong.com/regular-expressions/how-to-validate-ip-address-with-regular-expression/
      final String IPADDRESS_PATTERN =
      "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
      "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
      "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
      "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
      
      Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
      Matcher matcher;

      return Pattern.compile(IPADDRESS_PATTERN).matcher(ip).matches();
   }
   
   /**
    **   Extracts the data from the sent file.
    **/
   private static String parseResp(String resp) {
      return resp.replaceAll("##[A-Z]+##([^#]+)####", "$1");
   }
}
