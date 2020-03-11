import javax.swing.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random ;
import java.math.BigInteger; 
import java.util.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets; 
import java.security.MessageDigest;  
import java.security.NoSuchAlgorithmException;
import java.io.*;

class ALL3
{
byte[] skey = new byte[1000];
String skeyString;
static byte[] raw;
String inputMessage,encryptedData,decryptedMessage,w,w1;
public ALL3() 
{
try 
{
    int ch;
    inputMessage="";
	FileInputStream fin= new FileInputStream("file1.txt");
	while((ch=fin.read())!=-1) 
            inputMessage+=((char)ch);
    System.out.println(inputMessage);
    byte[] ibyte = inputMessage.getBytes();
    String k=JOptionPane.showInputDialog(null,"Choose type of encryption\n"+  "DES\n"+  "AES\n" + "TRIPLEDES\n");
    String k1=JOptionPane.showInputDialog(null,"Choose type of mode\n"+  "ECB\n"+  "CBC\n" + "CFB\n"+ "OFB\n"+"CTR\n");
    String s33=JOptionPane.showInputDialog(null,"Choose for integrity check\n"+  "SHA-256\n"+  "MD5\n" );
    w=toHexString(Integritycheck(inputMessage,s33));
    if(k1.toUpperCase().equals("ECB"))
    { 
        generateSymmetricKey(k);
        byte[] ebyte=encrypt(raw, ibyte,k);
        encryptedData = new String(ebyte);
        JOptionPane.showMessageDialog(null,"Encrypted Data "+"\n"+encryptedData,"After Encryption", JOptionPane.INFORMATION_MESSAGE);
        byte[] dbyte= decrypt(raw,ebyte,k);
        decryptedMessage = new String(dbyte);
        JOptionPane.showMessageDialog(null,"Decrypted Data "+"\n"+decryptedMessage,"After Decryption", JOptionPane.INFORMATION_MESSAGE);
        w1=toHexString(Integritycheck(decryptedMessage,s33));
    }
    else
    {
        generateSymmetricKey(k);
        int p=8;
        if(k.toUpperCase().equals("AES"))
        p=16;
        byte[] ebyte=Encrypt(raw,ibyte,k,k1,p);
        encryptedData = new String(ebyte);
        JOptionPane.showMessageDialog(null,"Encrypted Data "+"\n"+encryptedData,"After Encryption", JOptionPane.INFORMATION_MESSAGE);
        byte[] dbyte= Decrypt(raw,ebyte,k,k1,p);
        decryptedMessage = new String(dbyte);
        JOptionPane.showMessageDialog(null,"Decrypted Data "+"\n"+decryptedMessage,"After Decryption", JOptionPane.INFORMATION_MESSAGE);
        w1=toHexString(Integritycheck(decryptedMessage,s33));
    }
        System.out.println("Encrypted message "+encryptedData);
        System.out.println("Decrypted message "+decryptedMessage);
        FileOutputStream fout=new FileOutputStream("file2.txt");
        fout.write(decryptedMessage.getBytes());
        if(w.equals(w1))
        {
            JOptionPane.showMessageDialog(null,"Integrity check is passed","Integrity Check", JOptionPane.INFORMATION_MESSAGE);
        }
        else
        {
            JOptionPane.showMessageDialog(null,"Integrity check is failed","Integrity Check", JOptionPane.ERROR_MESSAGE);
        }
}
catch(Exception e) 
{
    System.out.println(e);
}
}
void generateSymmetricKey(String s) throws Exception
{
    int k=0;
    if(s.toUpperCase().equals("AES")){k=Integer.parseInt(JOptionPane.showInputDialog(null,"Enter key size 192 ,128 ,256","Key Size", JOptionPane.INFORMATION_MESSAGE));}
    if(s.toUpperCase().equals("DES")){k=56;}
    if(s.toUpperCase().equals("TRIPLEDES")){k=Integer.parseInt(JOptionPane.showInputDialog(null,"Enter key size 112 ,168 ","Key Size", JOptionPane.INFORMATION_MESSAGE));}
    Random r = new Random();
    int num = r.nextInt();
    String knum = String.valueOf(num);
    byte[] knumb = knum.getBytes();
    skey=getRawKey(knumb,s,k);
    Random sc = new SecureRandom();
    skeyString = new String(skey);
    System.out.println("Symmetric key= "+skeyString);
}
public static byte[] Integritycheck(String input,String s) throws NoSuchAlgorithmException 
{
    MessageDigest md = MessageDigest.getInstance(s);  
    return md.digest(input.getBytes(StandardCharsets.UTF_8));
} 
public static String toHexString(byte[] hash) 
{ 
    BigInteger number = new BigInteger(1, hash); 
    StringBuilder hexString = new StringBuilder(number.toString(16));   
    while (hexString.length() < 32){hexString.insert(0, '0');}  
    return hexString.toString();
} 
private static byte[] getRawKey(byte[] seed,String s,int key) throws Exception 
{
    KeyGenerator kgen = KeyGenerator.getInstance(s);
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    sr.setSeed(seed);
    kgen.init(key, sr);
    SecretKey skey = kgen.generateKey();
    raw = skey.getEncoded();
    return raw;
}
private static byte[] encrypt(byte[] raw, byte[] clear,String s) throws Exception
{
    SecretKeySpec skeySpec = new SecretKeySpec(raw, s);
    Cipher cipher = Cipher.getInstance(s+"/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
    byte[] encrypted = cipher.doFinal(clear);
    return encrypted;
}
private static byte[] decrypt(byte[] raw, byte[] encrypted,String s) throws Exception 
{
    SecretKeySpec skeySpec = new SecretKeySpec(raw, s);
    Cipher cipher = Cipher.getInstance(s+"/ECB/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, skeySpec);
    byte[] decrypted = cipher.doFinal(encrypted);
    return decrypted;
}
public static byte[] Encrypt(byte[] raw,byte[] clear,String s,String s1,int p) throws Exception 
{
    IvParameterSpec iv = new IvParameterSpec(new byte[p]);
    SecretKeySpec skeySpec = new SecretKeySpec(raw, s);
    SecretKeySpec s11=new SecretKeySpec(raw,s);
    Cipher cipher = Cipher.getInstance(s+"/"+s1+"/PKCS5PADDING");
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
    byte[] encrypted = cipher.doFinal(clear);
    return encrypted;
}
public static byte[] Decrypt(byte[] raw,byte[] encrypted,String s,String s1,int p) throws Exception 
{
    IvParameterSpec iv = new IvParameterSpec(new byte[p]);
    SecretKeySpec skeySpec = new SecretKeySpec(raw,s);
    Cipher cipher = Cipher.getInstance(s+"/"+s1+"/PKCS5PADDING");
    cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
    byte[] original = cipher.doFinal(encrypted);
    return original;
}
public static void main(String args[]) 
{
ALL3 all = new ALL3();
}
}