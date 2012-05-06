import java.io.BufferedReader;


public class InputHelper
{
	BufferedReader in;
	
	InputHelper(BufferedReader in)
	{
		this.in = in;
	}
	
	public String readLine(String prompt)
	{
		String command = "(null)";
		try 
		{
			System.out.print(prompt);
			command = in.readLine();
		}
		catch(Exception e)
		{
			e.printStackTrace();
			System.out.println("InputHelper.readLine():  Could not input message.");
		}
		return command;
	}
}