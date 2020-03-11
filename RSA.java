import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.MessageDigest;
import java.util.*;

import java.io.*; 

import javax.crypto.Cipher;

public class RSA {
   public static void main(String args[]) throws Exception{
      KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
      keyPairGen.initialize(2048);
      KeyPair pair = keyPairGen.generateKeyPair();   
      String pt="";
   FileInputStream fin=new FileInputStream("file1.txt");
   FileOutputStream fout=new FileOutputStream("file2.txt");
         int ch; 
        while((ch=fin.read())!=-1) 
           pt+=(char)ch; 
Scanner in=new Scanner(System.in);
byte[] input = pt.getBytes();
//message digest
System.out.println("Choose an integrity check 1.MD5 2.SHA1");
int y=in.nextInt();String hh="";
if(y==1)hh="MD5";
if(y==2)hh="SHA1";
 Signature instance = Signature.getInstance(hh+"withRSA");
instance.initSign(pair.getPrivate());
instance.update(input);
byte[] signature = instance.sign();
String signa=new String(signature);
MessageDigest sha1 = MessageDigest.getInstance("SHA1");
byte[] digest = sha1.digest(input);
String dig=new String(digest);
      //Creating a Cipher objectsz
      String s="";
      System.out.println("Choose type of RSA--> 1.RSA 2.RSA-ECB mode");
      int k=in.nextInt();
      if(k==1)s="RSA";
      if(k==2) s="RSA/ECB/PKCS1Padding";
      Cipher cipher = Cipher.getInstance(s);

      //Initializing a Cipher object
      cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
	  
      //Add data to the cipher
      	  
      cipher.update(input);
	  
      //encrypting the data
      byte[] cipherText = cipher.doFinal();	 
      System.out.println( "Cipher text:\n"+ new String(cipherText, "UTF8"));
      //String h=new String(cipherText, "UTF8");
      //fout.write(h.getBytes());
      //System.out.println("Digest:\n"+dig);
      //System.out.println("Signature:\n"+signa);

      //Initializing the same cipher for decryption
      cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
      
      //Decrypting the text
      byte[] decipheredText = cipher.doFinal(cipherText);
      System.out.println("Decryptrd text:\n"+new String(decipheredText));
      String s1=new String(decipheredText);
      //fout.write(" ".getBytes());
        fout.write(s1.getBytes());
   }
}