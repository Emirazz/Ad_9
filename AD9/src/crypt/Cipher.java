package crypt;

import java.math.BigInteger;
import java.util.Base64;
import java.util.Random;

public class Cipher {

	/**
	 * the plain data, that should be secured by encryption
	 */
	public String plaintext;
	
	/**
	 * the plain data, in form of an byte array
	 */
	public byte[] byte_plaintext;
	
	/**
	 * the size of every block
	 */
	public final int BLOCK_SIZE = 16;
	
	/**
	 * the offset at the end of the byte array 
	 */
	public int offset;
	
	/**
	 * the padding at the beginning of the byte array 
	 */
	public final int PADDING = 16;
	
	/**
	 * the placeholder, that the offset is filled with (content = 35 = '#')
	 */
	public final byte PLACEHOLDER = 0x20;
	
	/**
	 * the size of the sessionkey
	 */
	public final int SESSIONSKEY_SIZE = 8;
	
	/**
	 * the plain session key, that is used for the feistel network
	 */
	public byte[] sessionkey;
	
	/**
	 * number of rounds of the feistel network
	 */
	public final int ROUNDS = 12;
	
	/**
	 * the encrypted data
	 */
	public byte[] cipheredtext;
	
	/**
	 * array of feistelblocks
	 */
	FeistelBlock[] fb;

	private byte[] cipheredsessionkey;
	
	/**
	 * ##CONSTRUCTOR##
	 */
	public Cipher() {
		
		this.plaintext = "";
		this.byte_plaintext = new byte[1];
		this.offset = 0;
		this.sessionkey = new byte[1];
		this.cipheredtext = new byte[1];
		this.fb = new FeistelBlock[1];
	}
	
	/**
	 * ##encrypts a String with the RSA encryption##
	 * 
	 * @param s:String the plaintext that should be encrypted 
	 * @param rsa:RSA
	 * @return encrypted text
	 */
	public String encrypt(String s, RSA rsa) {
		
		plaintext = s;
		byte_plaintext = plainToByte(plaintext);
		addOffset();
		addPlaceholder();
		createSessionkey();
		for(int i = 0;i< byte_plaintext.length; i+= BLOCK_SIZE) {
			byte[]block = blockencrypt(byte_plaintext,i,sessionkey);
			System.arraycopy(block,0, byte_plaintext,i, BLOCK_SIZE);
			
		}
		cipheredsessionkey = BigInt2Byte(rsa.encipherRSA(Byte2BigInt(sessionkey)), 16);
		byte[] output = new byte[cipheredsessionkey.length + byte_plaintext.length];
		System.arraycopy(cipheredsessionkey, 0, output, 0, cipheredsessionkey.length);
		System.arraycopy(byte_plaintext, 0, output, cipheredsessionkey.length, byte_plaintext.length);
		return base64Encode(output);
	}
	
	public String decrypt(String s,RSA rsa) {
		byte[] encrypted = base64Decode(s);
		cipheredsessionkey = new byte[16];
		System.arraycopy(encrypted, 0, cipheredsessionkey, 0, 16);
		sessionkey = BigInt2Byte(rsa.decipherRSA(Byte2BigInt(cipheredsessionkey)), 16);
		byte_plaintext = new byte[encrypted.length - cipheredsessionkey.length];
		for(int i = cipheredsessionkey.length;i< encrypted.length; i+= BLOCK_SIZE) {
			byte[]block = blockdecrypt(encrypted,i,sessionkey);
			System.arraycopy(block,0, byte_plaintext,i - BLOCK_SIZE, BLOCK_SIZE);
			
			
		}
		return new String(byte_plaintext);
	}
	
	private byte[] blockencrypt(byte[] b, int i, byte[] key) {
		FeistelBlock block  = new FeistelBlock(b,i); 
		for (int j = 0; j < 12; j++) {
		      block.round(key);
		    }
		return block.getBlock();
	}
	
	private byte[] blockdecrypt(byte[] b, int i, byte[] key) {
		FeistelBlock block  = new FeistelBlock(b,i); 
		  block.swap();
		for (int j = 0; j < 12; j++) {
		      block.round(key);
		    }
		 block.swap();
		return block.getBlock();
	}
	/**
	 * ##creates byte array out of a String##
	 * 
	 * @param plaintext:String
	 * @return byte[]
	 */
	public byte[] plainToByte(String s) {
		return s.getBytes();
	}
	
	/**
	 * ##adds offset to byte arr##
	 * 
	 * @param  --
	 * @return --
	 */
	public void addOffset() {
		if (byte_plaintext.length % BLOCK_SIZE != 0) {
			
			offset = (BLOCK_SIZE - (byte_plaintext.length % BLOCK_SIZE));
			byte[] temp = new byte[byte_plaintext.length + offset];
			System.arraycopy(byte_plaintext, 0, temp, 0, byte_plaintext.length);
			byte_plaintext = temp;
		}
	}
	
	/**
	 * ##adds padding to byte arr##
	 * 
	 * @param  --
	 * @return --
	 */
	public void addPadding() {
		byte[] temp = new byte[byte_plaintext.length + PADDING];
		System.arraycopy(byte_plaintext, 0, temp, PADDING, byte_plaintext.length);
		byte_plaintext = temp;
	}
	
	/**
	 * ##adds placeholder to empty padding and offset of the arr##
	 * 
	 * @param  --
	 * @return --
	 */
	public void addPlaceholder() {
		
		for(int i = byte_plaintext.length - offset;i < byte_plaintext.length;i++) {
			byte_plaintext[i] = PLACEHOLDER;
		}
	}
	
	/**
	 * ##creates sessionkey##
	 * 
	 * @param  --
	 * @return --
	 */
	public void createSessionkey() {
		
		byte[] temp = new byte[SESSIONSKEY_SIZE];
		for (int i = 0; i < SESSIONSKEY_SIZE; i++) {
			temp[i] = ((byte) rndInt(0, 127));
		}
		sessionkey = temp;
	}
	
	/**
	 * 
	 * @param min
	 * @param max
	 * @return
	 */
	public int rndInt(int min, int max) {
		Random rnd = new Random();
		return rnd.nextInt(max - min + 1) + min;
	}

	/**
	 * ##feistel network with 12 rounds using the same key##
	 * 
	 * @param b:byte[] (plaintext)
	 * @param key:byte[] (sessionkey)
	 * @return ciphered text
	 */
	public byte[] blockencrypt(byte[] b,byte[] key) {
		
		byte[] cipher = new byte[b.length];
//		fb = new FeistelBlock[b.length / BLOCK_SIZE];
//		
//		for(int i = 0; i < fb.length;i++){
//			
//			byte[] cur_block = new byte[BLOCK_SIZE];
//			System.arraycopy(b, BLOCK_SIZE * (i+1), cur_block, 0, BLOCK_SIZE);
//			fb[i] = new FeistelBlock(cur_block);
//		}
//		
//		for (int i = 0; i < ROUNDS; i++) {
//			for(int j = 0; j < fb.length;j++){
//		      fb[j].round(key);
//			}
//		    }
//		for(int i = 0; i < fb.length;i++){
//			byte[] cur_block = fb[i].getBlock();
//			System.arraycopy(cur_block, 0, cipher, BLOCK_SIZE * (i+1), BLOCK_SIZE);

//		}
		
		return cipher;
	}
	
	public byte[] blockdecrypt(byte[] b,byte[] key) {
		byte[] decrypted = new byte[1];
//		for(int j = 0; j < fb.length;j++){
//			fb[j].swap();
//		}
//		decrypted = blockencrypt(b, key);
//		for(int j = 0; j < fb.length;j++){
//			fb[j].swap();
//		}
//		
		return decrypted;
	}
	/**
	 * ##creates BigInteger out of byte arr##
	 * 
	 * @param  b:byte []
	 * @return BigInteger
	 */
	public static BigInteger Byte2BigInt(byte[] b){
		return new BigInteger ( 1 , b );
		}
	
	/**
	 * ##creates byte arr out of BigInteger##
	 * ##GIVEN METHOD##
	 * @param  src:BigInteger
	 * @param  bytesize:int size of the byte arr that should be created
	 * @return byte arr
	 */
	public static byte[] BigInt2Byte (BigInteger src, int bytesize){
		byte[] out = new byte[bytesize];
		BigInteger mod = new BigInteger("2");
		mod = mod.pow(bytesize*8);
		src = src.mod(mod);
		int startdst = bytesize - src.toByteArray().length ;
		int cpylength = src.toByteArray().length;
		if((src.bitLength() % 8) != 0){
		System.arraycopy(src.toByteArray(),0,out,startdst,cpylength);
		}
		else {
		System.arraycopy(src.toByteArray(),1,out,startdst+1,cpylength-1);
		}
		return out;
		}
	/**
	 * ##decodes base64 String to byte arr##
	 * ##GIVEN METHOD##
	 * @param s:String base64
	 * @return byte[]
	 */
	public static byte[] base64Decode(String s)
	  {
	    return Base64.getDecoder().decode(s);
	  }
	  
	/**
	 * ##encodes byte arr into base64 String##
	 * @param bytes:byte[]
	 * @return String base64
	 */
	 public static String base64Encode(byte[] bytes) {
	    return Base64.getEncoder().encodeToString(bytes);
	 }
	
	@Override
	public String toString() {
		
		String erg = "";
		erg += "var plaintext:" + plaintext + "\n";
		erg += "var byte_plaintext:";
		for(byte b : byte_plaintext) {
			erg += b;
		}
		erg +=" length:" + byte_plaintext.length + "\n";
		erg += "const blocksize:" + BLOCK_SIZE + "\n";
		erg += "var offset:" + offset + "\n";
		erg += "const padding:" + PADDING + "\n";
		erg += "const placeholder:" + PLACEHOLDER + "\n";
		erg += "const sessionkey size:" + SESSIONSKEY_SIZE + "\n";
		erg += "var sessionkey:";
		for(byte b : sessionkey) {
			erg += b;
		}
		erg +=" length:" + sessionkey.length + "\n";
		erg += "const number of rounds:" + ROUNDS + "\n";
		erg += "var cipheredtext:";
		for(byte b : cipheredtext) {
			erg += b;
		}
		erg +=" length:" + cipheredtext.length + "\n";
		return erg;
	}
	

}
