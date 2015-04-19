import static java.lang.System.arraycopy;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;

/*
 * Class that holds the widely used Password Based Key Derivation Function 2
 */
public class PBKDF {
	
	 public static void pbkdf2(Mac mac, byte[] Salt, int c, byte[] DK, int dkLen) throws GeneralSecurityException {
	        int macLength = mac.getMacLength();
	        int saltLength = Salt.length;
	        
	        //Set up 2 temp arrays and the blocks array
	        byte[] tempArray1 = new byte[macLength];
	        byte[] tempArray2 = new byte[macLength];
	        byte[] blocks = new byte[saltLength + 4];

	        //Determine the number of loop iterations by output length divided by hte mac length
	        int loop = (int) Math.ceil((double) dkLen / macLength);
	        int r = dkLen - (loop - 1) * macLength;

	        arraycopy(Salt, 0, blocks, 0, saltLength);

	        //In a loop, perform the 'pseudo-random function' on the values in blocks, and update the HMAC
	        for (int i = 1; i <= loop; i++) {
	            blocks[saltLength + 0] = (byte) (i >> 24 & 0xff);
	            blocks[saltLength + 1] = (byte) (i >> 16 & 0xff);
	            blocks[saltLength + 2] = (byte) (i >> 8  & 0xff);
	            blocks[saltLength + 3] = (byte) (i >> 0  & 0xff);

	            //Upon update, the HMAC does its Hash
	            mac.update(blocks);
	            mac.doFinal(tempArray1, 0);
	            arraycopy(tempArray1, 0, tempArray2, 0, macLength);

	            //Set up some variables for cloning the array
	            int destPosition = (i-1)*macLength;
	            int copyLength = 0;
	            if(i==loop){
	            	copyLength = r;
	            } else {
	            	copyLength = macLength;
	            }
	            //Update the output DK and loop again
	            arraycopy(tempArray2, 0, DK, destPosition, copyLength);
	        }
	 }

}
