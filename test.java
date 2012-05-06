import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.FormattableFlags;

public class test 
{
	public static String[] commands = {"help", 
										"hi", 
										"exit",
										"myKey",
										"caKey",
										"newRSAKey",
										"oldRSAKey",
										"recoverRSAPrivateKey",
										"encryptMessage",
										"decryptMessage",
										"digest",
										"sign"
										};
	
	public static String[] commandDescriptions = {"help, prints this menu", 
												"hi", 
												"exit", 
												"print out myKey",
												"print out caKey",
												"generate new RSA Keys", 
												"reuse existing RSA Keys", 
												"attack an RSA Public Key", 
												"encrypt a Plaintext Message",
												"decrypt a Cyphertext Message",
												"get the truncated MD5 Hash of a Message", 
												"get the signed truncated MD5 Hash of a Message" 
												};	
	
	public static void printCommands()
	{
		System.out.println("The commands are:");
		System.out.println("    COMMAND                  DESCRIPTION");
		for (int i = 0; i<commands.length;i++)
		{
			System.out.printf("%2d. %-24s %s\n", i,commands[i],commandDescriptions[i]);
		}
	}
	
	public static void printHelp()
	{
		printCommands();
	}
	
	static RSA myKey = null;
	static RSA caKey = null;
	static RSA signersKey = null;
	static MD5Hash hasher = new MD5Hash();
	
	public static void setKey(InputHelper c, RSA k)
	{
		String response;
		
		do {
			response = c.readLine("Set myKey?: ");
		} while (!response.startsWith("y")&&!response.startsWith("Y")&&!response.startsWith("n")&&!response.startsWith("N"));
		
		if (response.startsWith("y")||response.startsWith("Y"))
		{
			myKey = k;
		}
			
		do {
			response = c.readLine("Set caKey?: ");
		} while (!response.startsWith("y")&&!response.startsWith("Y")&&!response.startsWith("n")&&!response.startsWith("N"));
		
		if (response.startsWith("y")||response.startsWith("Y"))
		{
			caKey = k;
		}	
	}
	
	public static RSA chooseKey(InputHelper c)
	{
		String response;
		
		do {
			response = c.readLine("use myKey?: ");
		} while (!response.startsWith("y")&&!response.startsWith("Y")&&!response.startsWith("n")&&!response.startsWith("N"));
		
		if (response.startsWith("y")||response.startsWith("Y"))
		{
			return myKey;
		}
		do {
			response = c.readLine("use caKey?: ");
		} while (!response.startsWith("y")&&!response.startsWith("Y")&&!response.startsWith("n")&&!response.startsWith("N"));
		
		if (response.startsWith("y")||response.startsWith("Y"))
		{
			return caKey;
		}
		return null;
	}
	
	public static void main(String args[])
    {
            System.out.println("Crypto Shell\n");

            InputStreamReader stream = new InputStreamReader(System.in);
    		BufferedReader in = new BufferedReader(stream);
    		InputHelper c = new InputHelper(in);
    		
    		System.out.println("The system default charset is: "+ Charset.defaultCharset());	
        	System.out.println("type help for a list of commands.");            
            while(true)
            {
            	String command = c.readLine("command:> ");
            	System.out.println("<"+command+">");
            	
            	if (command.startsWith("hi"))
            	{
            		System.out.println("hi.");
            	}
            	else if (command.startsWith("help"))
            	{
            		printHelp();
            	}
            	else if (command.startsWith("exit"))
            	{
            		System.out.println("bye!");
            		break;
            	}

            	else if (command.startsWith("my"))
            	{
            		if (myKey==null)
            		{
            			System.out.println("myKey is (null)");
            		}
            		else
            		{
            			myKey.printKeys();
            		}
            	}
            	else if (command.startsWith("ca"))
            	{
            		if (caKey==null)
            		{
            			System.out.println("caKey is (null)");
            		}
            		else
            		{
            			caKey.printKeys();
            		}
            	}

            	else if (command.startsWith("new"))
            	{	
            		RSA newRSA = new RSA();
            		newRSA.printKeys();
            		setKey(c, newRSA);
            	}
            	else if (command.startsWith("old"))
            	{
            		System.out.println("Enter the existing RSA Key");
            		
            		command = c.readLine("p:");
            		BigInteger p = new BigInteger(command);
            		System.out.println("you entered <<"+p.toString()+">>");
            		
            		command = c.readLine("q:");
            		BigInteger q = new BigInteger(command);
            		System.out.println("you entered <<"+q.toString()+">>");
            		
            		command = c.readLine("e:");
            		BigInteger e = new BigInteger(command);
            		System.out.println("you entered <<"+e.toString()+">>");

            		RSA oldRSA = new RSA(p, q, e);
            		oldRSA.printKeys();
            		setKey(c, oldRSA);
            	}
            	else if (command.startsWith("recover"))
            	{
            		System.out.println("Enter the existing RSA Key");
            		
            		command = c.readLine("N:");
            		BigInteger N = new BigInteger(command);
            		System.out.println("you entered <<"+N.toString()+">>");
            		
            		command = c.readLine("e:");
            		BigInteger e = new BigInteger(command);
            		System.out.println("you entered <<"+e.toString()+">>");
            		
            		RSA recoveredRSA = new RSA(N,e);
            		System.out.print("Attacking RSA Key....");
            		double elapsedTime = (double)recoveredRSA.recoverPrivateKey();
            		System.out.println("DONE! ("+elapsedTime/1000+" sec)");
            		
            		recoveredRSA.printKeys();
            		setKey(c, recoveredRSA);
            	}
            	else if (command.startsWith("enc"))
            	{
            		if (myKey==null)
            		{
            			System.out.println("please set myKey first");
            		}
            		else
            		{
                		String message = c.readLine("Enter plaintext: ");
                		String cyphertext = "cyphertext";
                		//String plaintext = "plaintext";
                		
                		try 
                		{
            				cyphertext = myKey.encrypt(message);
            				//plaintext = myKey.decrypt(cyphertext);
            			} 
                		catch (Exception e1) 
                		{
            				e1.printStackTrace();
            			}
                		
                		System.out.println("Cyphertext: " + cyphertext);
                		
                		//System.out.println("Message   : <<"+message+">>");
                		//System.out.println("Cyphertext: <<"+cyphertext+">>");
                		//System.out.println("Plaintext : <<"+plaintext+">>");
            		}
            		
            	}
            	else if (command.startsWith("dec"))
            	{
            		if (myKey==null)
            		{
            			System.out.println("please set myKey first");
            		}
            		else
            		{
                		String message = c.readLine("Enter cyphertext: ");
                		//String cyphertext = "cyphertext";
                		String plaintext = "plaintext";
                		
                		try 
                		{
            				plaintext = myKey.decrypt(message);
            				//cyphertext = myKey.encrypt(plaintext);
            			} 
                		catch (Exception e1) 
                		{
            				e1.printStackTrace();
            			}
                		
                		System.out.println("Plaintext : " + plaintext);
                		
                		//System.out.println("Message   : <<"+message+">>");
                		//System.out.println("Plaintext : <<"+plaintext+">>");
                		//System.out.println("Cyphertext: <<"+cyphertext+">>");
            		}
            		
            	}
            	else if (command.startsWith("di"))
            	{
            		String message = c.readLine("Enter message: ");
            		String hash = hasher.computeHash(message);
            		System.out.println("MD5 (truncated): " + hash);
            	}
            	
            	else if (command.startsWith("si"))
            	{
            		signersKey = chooseKey(c);
            		if (signersKey==null)
            		{
            			System.out.println("that key is not set");
            		}
            		else
            		{
                		String message = c.readLine("Enter message: ");
                		String hash = hasher.computeHash(message);
                		System.out.println("MD5 (truncated): " + hash);
                		String signature = null;
                		try 
                		{
                			signature = signersKey.sign(hash);
						} 
                		catch (Exception e) 
                		{
							e.printStackTrace();
						}
                		System.out.println("Signature: " + signature);
            		}	
            	}
            	else 
            	{
            		System.out.println("unknown command.  try help");
            	}
            }
    }
}
