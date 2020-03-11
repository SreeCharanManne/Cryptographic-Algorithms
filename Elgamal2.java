import java.math.*;
import java.util.*;
import java.security.*;
import java.io.*;
import java.math.BigInteger; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;
import java.awt.*;
import java.awt.event.*;

public class ElGamal2 extends Frame implements ActionListener
{  
    Button b1 = new Button("Encrypt");
    Button b2 = new Button("Decrypt");
	Label l1=new Label("Plain Text");
	Label l2=new Label("Decrypted Text");
	Label l3=new Label("Cipher Text");
    Label l4=new Label("Integritiy Check Algo");
	TextArea t1 = new TextArea();
	TextArea t2 = new TextArea();
	TextArea t3 = new TextArea();
    TextArea t4 = new TextArea();
	static String f1="";
    static String f2="";	
	public ElGamal2()
	{add(l1);add(t1);add(l4);add(t4);add(l3);add(t2);add(l2);add(t3); add(b1);	add(b2);
        setLayout(new GridLayout(5, 1));
		setSize(1000,500);
		setVisible(true);
		setTitle("ElGamal Algo");
		b1.addActionListener(this);
		b2.addActionListener(this);
		addWindowListener(new WindowAdapter()
           {
                public void windowClosing(WindowEvent e)
                {
                    System.exit(0);
                }
           });
	}
	public void actionPerformed(ActionEvent ae)
	{Graphics g; 
		if(ae.getSource()==b1)
		{encrypt(t1.getText(),t4.getText());
			t2.setText(""+f1);
		}
		if(ae.getSource()==b2)
		{
		t3.setText(f2);
		}
	}
	public static void encrypt(String s1,String hg)
	{String s=s1;
        BigInteger p, b, c, secretKey;
        Random sc = new SecureRandom();
        secretKey = new BigInteger(64, sc);
        //
        // public key calculation
        //
        System.out.println("secretKey = " + secretKey+"\n");
		System.out.println(s);
        p = BigInteger.probablePrime(64, sc);//q
        b = new BigInteger("3");
        c = b.modPow(secretKey, p);
        System.out.println("p = " + p+"\n");
        System.out.println("b = " + b+"\n");
        System.out.println("c = " + c+"\n");
        //
        // Encryption
        //
        BigInteger X = new BigInteger(s);
        System.out.println(X);
        BigInteger r = new BigInteger(64, sc);
        BigInteger EC = X.multiply(c.modPow(r, p)).mod(p);
		f1=""+EC;
        
        BigInteger brmodp = b.modPow(r, p);
        System.out.println("Plaintext = " + X+"\n");
        System.out.println("r = " + r);
        System.out.println("EC = " + EC+"\n");
		System.out.println("Hash of Plain text -->"+IntChe(""+s,hg)+"\n");
        System.out.println("b^r mod p = " + brmodp);
		//
        // Decryption
        //
        BigInteger crmodp = brmodp.modPow(secretKey, p);
        BigInteger d = crmodp.modInverse(p);
        BigInteger ad = d.multiply(EC).mod(p);
        System.out.println("\n\nc^r mod p = " + crmodp+"\n");
        System.out.println("d = " + d+"\n");
        System.out.println("decoded text: " + ad+"\n");
		f2=""+ad;
		
		System.out.println("Hash of Decrypted text -->"+IntChe(""+f2,hg)+"\n");
	}
	
    public static String IntChe(String input,String f) 
    { 
        try { 
            MessageDigest md = MessageDigest.getInstance(f); 
            byte[] messageDigest = md.digest(input.getBytes()); 
            BigInteger no = new BigInteger(1, messageDigest); 
            String hashtext = no.toString(16); 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
            return hashtext; 
        }  
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 
    public static void main(String[] args) throws IOException
    { 
        new ElGamal2();
    }
}