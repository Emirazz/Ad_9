package crypt;

import java.math.BigInteger;

/**
 * 
 */
public class FeistelBlock {
	
	/**
	 * right half of the feistelblock
	 */
	public byte[] right;
	
	/**
	 * left half of the feistelblock
	 */
	public byte[] left;
	/**
	 * size of every block 
	 */
	public final int BLOCK_SIZE;
	
	/**
	 * startpoint of the block
	 */
	public int start;
	
	/**
	 * ##CONSTRUCTOR##
	 * 
	 * @param current byte block
	 */
	public FeistelBlock(byte[] b, int i) {
		this.BLOCK_SIZE = 16;
		this.start = i;
		left = new byte[BLOCK_SIZE/2];
		right = new byte[BLOCK_SIZE/2];
		System.arraycopy(b, i, left, 0, BLOCK_SIZE/2);
		System.arraycopy(b, i + BLOCK_SIZE/2, right, 0, BLOCK_SIZE/2);
	}

	/**
	 * ##swaps left and right half of the feistelblock
	 * 
	 * @param  --
	 * @return --
	 */
	public void swap() {
		byte[] templeft = new byte[right.length];
		System.arraycopy(right, 0, templeft, 0, right.length);
		System.arraycopy(left, 0, right, 0, left.length);
		System.arraycopy(templeft, 0, left, 0, left.length);

	}
	
	/**
	 * ##bitwise xor with the sessionkey##
	 * 
	 * @param a:byte[] result of function f() 
	 * @param key:byte[] sessionkey
	 * @return byte[] result
	 */
	public byte[] xor(byte[] a,byte[] key){
		 byte[] res = new byte[a.length];
		    for (int i = 0; i < a.length; i++) {
		     // res[i] = ((byte)(a[i] ^ key[(i % key.length)]));
		    	 res[i] = ((byte)(a[i] ^ key[(i)]));
		    }
		    return res;
	}
	/**
	 * ##one feistelround##
	 * 
	 * @param key:byte[] sessionkey
	 */
	public void round(byte[] key){
		//swap();
		//right = xor(f(right,key),key);
		byte[] temp = right;
		right = xor(left,f(right,key));
		left = temp;
		//TEST
//		System.out.print("TEST: ");
//		for(byte singlebyte : left) {
//		System.out.print( singlebyte + " ");
//	}
//		for(byte singlebyte : right) {
//		System.out.print( singlebyte + " ");
//	}
//		System.out.println();
	}
	/**
	 * ##encrypting method f()##
	 * 
	 * @param right half of the feistelblock
	 * @param key:byte[] sessionkey
	 * @return
	 */
	private byte[] f(byte[] right, byte[] key) {
		BigInteger BIGINT_RIGHT = Cipher.Byte2BigInt(right);
		BigInteger BIGINT_KEY = Cipher.Byte2BigInt(key);
		//Math.pow(2, 64)-1 = 18446744073709551615
		BigInteger res = BIGINT_RIGHT.multiply(BIGINT_RIGHT).add(BIGINT_KEY).mod(new BigInteger("18446744073709551615"));
		return Cipher.BigInt2Byte(res, right.length);
	}
	
	/**
	 * ##GETTER##
	 * @return byte[] block
	 */
	public byte[] getBlock(){
		byte[] res = new byte[BLOCK_SIZE];
		System.arraycopy(left, 0, res, 0, BLOCK_SIZE/2);
		System.arraycopy(right, 0, res, BLOCK_SIZE/2,BLOCK_SIZE/2);
		return res;
	}
}
