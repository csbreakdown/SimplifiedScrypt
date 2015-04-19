import static java.lang.System.arraycopy;

/*
 * This is the SMIX memory hard function used in Scrypt
 */
public class SMIX {
	
	public static void smix(byte[] B, int Bi, int r, int N, byte[] V, byte[] XY) {
        int X = 0;
        int Y = 128 * r;
        int i;

        arraycopy(B, Bi, XY, X, 128 * r);

        for (i = 0; i < N; i++) {   //The loop is the size of N which is the CPU cost parameter, this applies pressure to the CPU
            arraycopy(XY, X, V, i * (128 * r), 128 * r);
            Hashing.blockMix(XY, X, Y, r); //Perform blockmix on the XY array
        }

        for (i = 0; i < N; i++) {
            int j = Hashing.integerify(XY, X, r) & (N - 1); //Convert XY into an integer
            Hashing.blockXor(V, j * (128 * r), XY, X, 128 * r); //Perform the boolean BlockXor function on the input and the altered array so far
            Hashing.blockMix(XY, X, Y, r); //Perform blockmix on XY again
        }

        arraycopy(XY, X, B, Bi, 128 * r); //Clone the array when the operations are done
    }

}
