import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Hash 
{
	public static final int DEFAULT_TRUNCATION = 4;
	public int truncation = DEFAULT_TRUNCATION;
	MessageDigest md = null;
	
	MD5Hash()
	{
		try 
		{
			md = MessageDigest.getInstance("MD5");
		} 
		catch (NoSuchAlgorithmException e) 
		{
			e.printStackTrace();
		}
	}
	
	public BigInteger computeHash(BigInteger input)
	{
		byte[] hash = null;
		hash = md.digest(input.toByteArray());
		byte[] truncatedHash = new byte[truncation];
		for (int j=0; j<truncation; j++)
		{	
			truncatedHash[j] = hash[j]; 
		}
		BigInteger h = new BigInteger(1, truncatedHash);
		return h;
	}
	
	public String computeHash(String input)
	{
		BigInteger i = null;
		try 
		{
			i = new BigInteger(1, input.getBytes("US-ASCII"));
		} 
		catch (UnsupportedEncodingException e) 
		{
			e.printStackTrace();
		}
		
		return computeHash(i).toString();
	}
}
