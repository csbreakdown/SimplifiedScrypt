import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/*
 * This is a simplified version of the Scrypt Algorithm by Colin Percival
 * Please note: This version is for educational purposes only. This version does not have many of the error catching
 * required to make it robust enough to be in production. Use at your own risk.
 * 
 * This code is a companion to the video on Scrypt Algorithms found at CSBreakdown.com
 * 
 * Any questions and comments? Contact me at karimhamasni@gmail.com
 * 
 * To run, simply execute the program and follow the prompt's in the console/cmd
 * 
 * References:
 * Colin Percival - Strong Key Derivation Via Sequential Memory-Hard Functions https://www.tarsnap.com/scrypt/scrypt.pdf
 * Will Glozer - http://glozer.net/
 * Daniel J. Bernstein - Salsa20 Algorithm Creator - http://cr.yp.to/papers.html
 *  
 */
public class MainProgram {
	
	public static void main(String[] args) throws NumberFormatException, GeneralSecurityException{
		
		String pwdString = "";
		String saltString = "";
		String cpuCostString = "";
		String memCostString = "";
		String parParamString = "";
		String dkLenString = "";
		
		try{
		    BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
		    System.out.println("Please enter a password: ");
		    pwdString = bufferRead.readLine();
	
		    System.out.println("Please enter a Salt String (eg. 'NaCl'): ");
		    saltString = bufferRead.readLine();
	 
		    System.out.println("Please enter a CPU Cost Parameter (eg. '1024'): ");
		    cpuCostString = bufferRead.readLine();
	 
		    System.out.println("Please enter a Memory Cost Parameter (eg. '8'): ");
		    memCostString = bufferRead.readLine();
	 
		    System.out.println("Please enter a Parallelization Paramater (eg. '16'): ");
		    parParamString = bufferRead.readLine();
		    
		    System.out.println("Please enter an output length (eg. '64'): ");
		    dkLenString = bufferRead.readLine();
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}
		
		byte[] password = pwdString.getBytes();
		byte[] salt = saltString.getBytes();
		
		byte[] passwordKey = scrypt(password, salt, Integer.parseInt(cpuCostString), Integer.parseInt(memCostString), Integer.parseInt(parParamString), Integer.parseInt(dkLenString));
		System.out.println("Password Key: ");
		for(byte b : passwordKey){
			System.out.print(String.format("%02X ", b));
		}
		
	}
	
	public static byte[] scrypt(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen) throws GeneralSecurityException {

        Mac mac = Mac.getInstance("HmacSHA256"); //We initialize a Message Authentication Code object that is based on the SHA256 algorithm (built into java)
        SecretKeySpec key = new SecretKeySpec(passwd, "HmacSHA256"); //The HMAC key is generated using SecretKeySpec built into Java
        mac.init(key); //HMAC is initialized

        byte[] finalOutput = new byte[dkLen]; //This is the byte array that will hold our eventual output

        byte[] blocksArray  = new byte[128 * r * p]; //This is an array that holds our blocks
        byte[] array1 = new byte[256 * r]; //Is a byte array that is 256 * the memory cost parameter used in the SMIX memory-hard algorithm
        byte[] array2  = new byte[128 * r * N]; //a byte array that is 128 * the memory cost parameter * the cpu cost parameter

        PBKDF.pbkdf2(mac, salt, 1, blocksArray, p * 128 * r);

        for (int i = 0; i < p; i++) {
            SMIX.smix(blocksArray, i * 128 * r, r, N, array2, array1);
        }

        PBKDF.pbkdf2(mac, blocksArray, 1, finalOutput, dkLen);

        return finalOutput;
    }

}
