package crypt;


import java.math.BigInteger;
import java.util.Random;


public class RSA {
	
	/**
	 * first random 64bit prime 
	 */
	public BigInteger prime1;
	
	/**
	 * second random 64bit prime
	 */
	public BigInteger prime2;
	
	/**
	 * const to calculate byte to bit
	 */
	public final int BYTE_TO_BIT_CONST = 8;

	/**
	 * main modulus
	 */
	private BigInteger modulus;

	/**
	 * side modulus
	 */
	public BigInteger phi;
	
	/**
	 * public key
	 */
	private BigInteger public_key;

	private BigInteger privatekey;
	/**
	 * ##CONSTRUCTOR##
	 */
	public RSA() {
		
		this.prime1 = new BigInteger("1");
		this.prime2 = new BigInteger("1");
		this.modulus = new BigInteger("1");
		this.phi = new BigInteger("1");
		this.public_key = new BigInteger("1");
		this.privatekey = new BigInteger("1");
	}
	
	/**
	 * ##creates a random number, which size is given through parameter##
	 * 
	 * @param bytelength:int 
	 * @return prime in BigInteger
	 */
	public BigInteger createPrime(int bytelength){
		Random rnd = new Random();
		return BigInteger.probablePrime(bytelength * BYTE_TO_BIT_CONST, rnd);
	}
	
	/**
	 * ##calculates the main modulus##
	 * 
	 * @param  --
	 * @return --
	 */
	public void calcMod(){
		modulus = prime1.multiply(prime2);
	}
	
	/**
	 * ##calculates the side modulus phi##
	 * 
	 * @param  --
	 * @return --
	 */
	public void calcPhi(){
		phi = prime1.subtract(BigInteger.ONE).multiply(prime2.subtract(BigInteger.ONE));
	}
	public void extractKey(String foreignkey){
		new Cipher();
		byte[] key = Cipher.base64Decode(foreignkey);
		byte[] foreignpublickey = new byte[8];
		byte[] foreignmod = new byte[16];
		System.arraycopy(key, 0, foreignpublickey, 0, 8);
	    System.arraycopy(key, 8, foreignmod, 0, 16);
	    public_key = Cipher.Byte2BigInt(foreignpublickey);
	    modulus = Cipher.Byte2BigInt(foreignmod);
		
	}
	public BigInteger encipherRSA(BigInteger in) {
	    return in.modPow(public_key, modulus);
	  }
	  
	  public BigInteger decipherRSA(BigInteger in)  {
	    if ((modulus == null) || (privatekey == null) || (modulus == BigInteger.ZERO)) {
	  System.out.println("Error:decipher");
	    }
	    return in.modPow(privatekey, modulus);
	  }
	  public BigInteger calcPrivateKey(){
		 return public_key.modInverse(phi);
	  }
	  
	  public String generateKeys(int bytelength){
			prime1 = createPrime(bytelength / 2);	
			prime2 = createPrime(bytelength / 2);
			calcMod();
			calcPhi();
			 Random rnd = new Random();
			    BigInteger key = BigInteger.probablePrime(64, rnd);
			    while (!phi.gcd(key).equals(BigInteger.ONE)) {
			      key = key.add(BigInteger.ONE);
			    }
			    public_key = key;
			    privatekey = calcPrivateKey();
			    



			    byte[] outbyte = new byte[bytelength + bytelength / 2];
			    

			    byte[] keybyte = Cipher.BigInt2Byte(public_key, bytelength / 2);
			    byte[] modulusbyte = Cipher.BigInt2Byte(modulus, bytelength);
			    System.arraycopy(keybyte, 0, outbyte, 0, bytelength / 2);
			    System.arraycopy(modulusbyte, 0, outbyte, bytelength / 2, bytelength);
			    
			    return Cipher.base64Encode(outbyte);
			}
	public void print(){
		System.out.println(toString());
	}
	@Override
	public String toString() {
		
		String erg = "";
		erg += "var prime1:" + prime1 + "\n";
		erg += "var prime2:" + prime2 + "\n";
		erg += "var modulus:" + modulus + "\n";
		erg += "var phi:" + phi + "\n";
		erg += "var public key:" + public_key + "\n";
	
		return erg;
	}
}