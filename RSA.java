import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA 
{
	//64 bits can hold a 16 US-ASCII chars
	public static final int DEFAULT_BIT_LENGTH = 64;
	private int bitLength = DEFAULT_BIT_LENGTH;

	public static final BigInteger ZERO = BigInteger.ZERO;
	public static final BigInteger ONE = BigInteger.ONE;
	public static final BigInteger TWO = new BigInteger("2");
	public static final BigInteger THREE = new BigInteger("3");
	public static final BigInteger FOUR = new BigInteger("4");
	
	
	public static SecureRandom random = null;

	static
	{
		if (random==null)
		{
			random = new SecureRandom();
		}
	}
	
	
	public boolean isThreeModFour(BigInteger x)
	{
		return x.mod(FOUR).equals(THREE);
	}
	
	public int getBitLength()
	{
		return bitLength;
	}

	public void setBitLength(int bitLength)
	{
		this.bitLength = bitLength;
	}
	
	private BigInteger p = null;
	private BigInteger q = null;
	private BigInteger phiN = null;
	private BigInteger d = null;
	private BigInteger e = null;
	private BigInteger N = null;
	
	public BigInteger getE()
	{
		return e;
	}
	
	public BigInteger getN()
	{
		return N;
	}
	
	public void printPublicKey()
	{
		System.out.println("Public Key:");
		System.out.println("N = " + N.toString()); 
		System.out.println("e = " + e.toString());
	}
	
	public void printPrivateKey()
	{
		System.out.println("Private Key:");
		System.out.println("p = " + p.toString()); 
		System.out.println("q = " + q.toString()); 
		System.out.println("phiN = " + phiN.toString()); 
		System.out.println("d = " + d.toString());
	}
	
	public void printKeys()
	{
		printPrivateKey();
		printPublicKey();
	}
	
	
	/**
	 * Input an old key for reuse.  
	 * 
	 * @param p
	 * @param q
	 * @param e
	 */
	RSA(BigInteger p, BigInteger q, BigInteger e)
	{
		this.p = p;
		this.q = q;
		this.e = e;
		N = p.multiply(q);
		phiN = p.subtract(ONE).multiply(q.subtract(ONE));
		d = e.modInverse(phiN);
	}
	
	
	/**
	 * Enter a public Key for cracking.  A subsequent call to the crack() method is required to actually to the cracking.
	 * 
	 * @param N
	 * @param e
	 */
	RSA(BigInteger N, BigInteger e)
	{
		//enter a public Key for cracking
		this.N = N;
		this.e = e;
	}
	
	/**
	 * This will attempt to factor N.  Afterwards, it will populate the rest of the private key.
	 * 
	 * @return the elapsed runtime in milliseconds
	 */
	public long recoverPrivateKey()
	{
		long startTime = System.currentTimeMillis();		
		
		if (p!=null)
			return (System.currentTimeMillis() - startTime);  //it's already factored
		
		try 
		{
			p = pollardsRho(N);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			return (System.currentTimeMillis() - startTime);
		}
		
		q = N.divide(p);
		phiN = p.subtract(ONE).multiply(q.subtract(ONE));
		d = e.modInverse(phiN);
		
		return (System.currentTimeMillis() - startTime);
	}
	
	/**
	 * Generate new public and private keys
	 * 
	 */
	RSA()
	{
		do {
			p = BigInteger.probablePrime(bitLength, random);
		} while (!isThreeModFour(p));
		
		do {
			q = BigInteger.probablePrime(bitLength, random);
		} while (!isThreeModFour(q));
		
		N = p.multiply(q);
		phiN = p.subtract(ONE).multiply(q.subtract(ONE));
		
		do {
			d = BigInteger.probablePrime(bitLength, random);
		} while (!d.gcd(phiN).equals(ONE));
		
		e = d.modInverse(phiN);
	}
	
	/**
	 * Performs the RSA encryption with the existing key
	 * 
	 * @param plaintext
	 * @return the encrypted cyphertext
	 */
	public BigInteger encrypt(BigInteger plaintext)
	{
		return plaintext.modPow(e, N);
	}
	
	/**
	 * Performs the RSA decryption with the existing key
	 * 
	 * @param cyphertext
	 * @return the decrypted plaintext 
	 */
	public BigInteger decrypt(BigInteger cyphertext)
	{
		//System.out.println("RSA.decrypt(): cyphertext = <<"+cyphertext.toString()+">>");
		return cyphertext.modPow(d, N);
	}
	
	/**
	 * Performs the RSA encryption with the existing key
	 * 
	 * @param plaintext in US-ASCII
	 * @return the encrypted cyphertext as a decimal number in US-ASCII
	 * @throws Exception if plaintext message is too long
	 */
	public String encrypt(String plaintext) throws Exception
	{
		BigInteger x = new BigInteger(plaintext.getBytes("US-ASCII"));
		if (x.compareTo(N)!=-1)
		{
			throw new Exception();
		}
		return encrypt(x).toString();
	}
	
	/**
	 * Performs the RSA decryption with the existing key
	 * 
	 * @param cyphertext as a decimal number in US-ASCII
	 * @return the decrypted plaintext in US-ASCII
	 * @throws Exception if cyphertext message is too long
	 */
	public String decrypt(String cyphertext) throws Exception
	{
		BigInteger x = new BigInteger(cyphertext);
		if (x.compareTo(N)!=-1)
		{
			throw new Exception();
		}
		return new String(decrypt(x).toByteArray());
	}
	
	/**
	 * Performs the RSA signature with the existing key
	 * 
	 * @param message as a decimal number in US-ASCII
	 * @return the RSA signed message as a decimal in US-ASCII
	 * @throws Exception if message is too long
	 */
	public String sign(String message) throws Exception
	{
		BigInteger x = new BigInteger(message);
		if (x.compareTo(N)!=-1)
		{
			throw new Exception();
		}
		return new String(decrypt(x).toString());
	}
		
	
	public BigInteger pollardsRho(BigInteger n) throws Exception 
	{
		BigInteger x = TWO;
		BigInteger y = (x.pow(2)).add(ONE);

		while (true) 
		{
			BigInteger g = x.subtract(y).abs().gcd(n);
			if (g.compareTo(ONE) != 0 && g.compareTo(n) != 0) 
			{
				return g;
			} 
			else if (g.equals(ONE)) 
			{
				x = ((x.pow(2)).add(ONE)).mod(n);
				y = (((y.pow(2).add(ONE)).pow(2)).add(BigInteger.ONE)).mod(n);
			} 
			else 
			{
				throw new Exception("Pollards Rho cannot break the value.");
			}
		}
	}
	
}
