package rsa.example.controller;


import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.MediaType;
import org.springframework.util.StopWatch;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.HandlerMapping;


@RestController
@RequestMapping(WarController.WAR_BASE_URI)
public class WarController {
	
	public static final String WAR_BASE_URI = "encryption";

	//Erstellen einer neuen Instanz der Klasse EuklidAlgorithm
	EuklidAlgorithm ea = new EuklidAlgorithm();
	//Erstellen einer neuen Instanz der Klasse SecureRandom -> Erzeugen eines ZufallGenerators
	//SecureRandom stellt einen sehr starken kryptographischen Zufallsgenerator zur Verfuegung
	SecureRandom randomGen = new SecureRandom();

	//BufferedReader zum Einlesen von Eingaben ueber die Konsole
	BufferedReader br = null;
	//Pfad zum File, welches verschluesselt werden soll
	String fileName = null;
	Path path = null;
	String getPath = null;
	String decryptPath = null;
	String oldFile = null;
	String oldFileDecr = null;
	
	//FileOutputStream wird benoetigt um ein neues File erstellen zu koennen
	FileOutputStream fos = null;
	FileOutputStream fosDecr = null;
	//PrintWriter wird benoetigt um ein beliebiges TextFile zu erstellen
	PrintWriter pw = null;
	
	String[] partsOfFileName = null;
	String fileDataType = null;
	byte[] data = null;
	byte[] decryptedResultAr = null;

	//Variablen-Deklaration
	//BigInteger wird verwendet, da der Wertebereich von Integer nicht ausreicht um 
	//z.B. 128-Bit Schluessel oder mehr zu generieren
	BigInteger ggT = new BigInteger("0");
	BigInteger decryptKey = null;
	BigInteger p = new BigInteger("0");
	BigInteger q = new BigInteger("0");
	BigInteger n = new BigInteger("0");
	BigInteger phi = new BigInteger("0");
	BigInteger e = new BigInteger("0");
	BigInteger tempDecryptKey = new BigInteger("0");
	
	//BigInteger-Array fuer die Berechnung des GGT und fuer das Verschluesselte-File
	BigInteger[][] ggtAr = null;
	BigInteger[] resultAr = null;
	
	int bitRange = 0;
	int count = 0;
	int countDecr = 0;
	
	static List<Double> logList = null;
	static List<Integer> keyList = null;
	
	static double recordEncr = 0;
	static double recordDecr = 0;
	StopWatch stopWatch = null;
	StringBuilder fileBuilderEncr = new StringBuilder();
	StringBuilder fileBuilderDecr = new StringBuilder();
			
	@RequestMapping(value = "/whereAmI",  produces=MediaType.ALL_VALUE)
	@ResponseBody
	public String getSystemInformation()
	{	
		StringBuilder sb = new StringBuilder();
		
		sb.append("<br />");
		sb.append(System.getProperty("os.name"));
		sb.append("<br />");
		sb.append(System.getProperty("os.version"));
		sb.append("<br />");
		sb.append(System.getProperty("os.arch"));
		sb.append("<br />");
		sb.append(System.getProperty("user.name"));
		sb.append("<br />");
		sb.append(System.getProperty("user.home"));
		
		return sb.toString();
	}


	@RequestMapping(value = "/getInformation", produces=MediaType.ALL_VALUE)
	@ResponseBody
	public String getInformation()
	{
		StringBuilder sb = new StringBuilder();
		
		sb.append("<br />");
		sb.append("<font size=\"3\" color=\"red\">" + "--RSA Encryption--" + "</font>");
		sb.append("<br />");
		sb.append("URI-getInformation: Get Information about possible options");
		sb.append("<br />");
		sb.append("URI-startProcess/file.extension/: Choose the file from your local machine to encrypt");
		sb.append("<br />");
		sb.append("URI-setBitRange/value: Choose the Bit-Range of public key");
		sb.append("<br />");
		sb.append("URI-startEncrypt: Encrypt File");
		sb.append("<br />");
		sb.append("URI-startDecrypt/PathToFile/: Decrypt File");
		
		return sb.toString();
	}
	
	
	@RequestMapping(value = "/startProcess/{setName}/**",produces = MediaType.ALL_VALUE)
	@ResponseBody
	public String startRSA(@PathVariable("setName") String setName, HttpServletRequest request)
	{
		try
		{
			StringBuilder sb = new StringBuilder();
			fileName = setName;
		
			//Einlesen des Pfads fuer beliebiges File
			String restOfURL = (String)request.getAttribute(
					HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE);
			
			int posOfFile = restOfURL.lastIndexOf(fileName);
			getPath = restOfURL.substring(posOfFile+fileName.length());
			
			path = Paths.get(getPath+fileName);
				
			
			//Aufsplitten von Dateitypen eines beliebigen Files z.B. test.txt -> txt
			partsOfFileName = fileName.split("\\.");
			//Beliebigen Datentyp als String speichern
			fileDataType = partsOfFileName[1];
		
			//Auslesen der Bytes eines beliebigen Files
			data = Files.readAllBytes(path);
			
			sb.append("<br />");
			sb.append("The file: \"");
			sb.append("<font size=\"3\" color=\"red\">" + setName + "</font>");
			sb.append("\" was found in: " + getPath);
			
			return sb.toString();
		
		}
		catch(Exception ex)
		{
			System.out.println(ex.getMessage());
		}
		return "\nThe file was not found!";
	}
	
	@RequestMapping(value = "setBitRange/{range}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
	@ResponseBody
	public String setBitRange(@PathVariable("range") int range)
	{
		try
		{
			StringBuilder sb = new StringBuilder();
			bitRange = range;
			
			//Generierung von zwei zufaelligen Primzahlen, mit der Bedingung: p!=q
			do
			{
				p = BigInteger.probablePrime(bitRange,randomGen);
				q = BigInteger.probablePrime(bitRange,randomGen);
			}while(p.compareTo(q)==0);
	
			//Berechnung des ersten public-keys -> n 
			n = p.multiply(q);
			
			//Berechnung der Eulerschen-Zahl
			phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
			
			e = new BigInteger("0");
			
			//Berechnung des zweiten public-keys -> e
			//mit den Bedingungen: 1< e <phi(n), e!=p, e!=q, ggt(e,phi)=1 
			do
			{
				//Generierung der zufaelligen Zahl e
				e = new BigInteger(bitRange,randomGen);
			
				if(e.compareTo(BigInteger.ONE)==1 && e.compareTo(p)!=0 && e.compareTo(q)!=0)
				{
					ggtAr = ea.ggT(phi,e);
					//Abfrage ob es einen GGT(phi,e)=1 gibt
					//je nach der Zeilen-Laenge im ggtAr[][] weiß man,
					//ob es einen GGT(phi,e)=1 gibt
					//falls ja (ggtAr.length>2) -> ggT befindet sich immer auf der gleichen Stelle im Array
					//falls nein -> ggT befindet sich ebenfalls immer auf der gleichen Stelle im Array
					if(ggtAr.length>2)
					{
						ggT = ggtAr[ggtAr.length-2][3];
					}
					else
					{
						ggT = ggtAr[0][1];
					}
				}
			}while(e.compareTo(n)==-1 && ggT.compareTo(BigInteger.ONE)!=0);
	
			//Private-Key d wird mithilfe der Methode advancedEuklid() berechnet
			decryptKey = ea.advancedEuklid(ggtAr);
			
			//Public-Keys und Private-Key werden in ein txt-File geschrieben
			//pw = new PrintWriter(new FileOutputStream("/home/boris/Documents/RSA_Files/keys.txt"));
			//pw.println("Public Key - e: " + e);
			//pw.println("Public Key - n: " + n);
			
			//Abfrage ob d < 0 ist, falls ja muss phi(n) dazu-addiert werden
			if(decryptKey.compareTo(BigInteger.ZERO)==-1)
			{
				tempDecryptKey = decryptKey.add(phi);
				//pw.println("Private Key - d: " + tempDecryptKey);
			}
			else
			{
				//pw.println("Private Key - d: " + decryptKey);
			}
			sb.append("\n");
			sb.append("BitRange of Public-Key set to: " + range);
			//pw.close();
			return sb.toString();
		}
		catch(Exception ex)
		{
			System.out.println(ex.getMessage());
		}
		return null;
	}
	
	@RequestMapping(value = "/startEncrypt")
	@ResponseBody
	public String encryptFileREST()
	{
		try
		{
			StringBuilder sb = new StringBuilder();
				
			stopWatch = new StopWatch("Monitor-Encryption");
			logList = new ArrayList<Double>();
			keyList = new ArrayList<Integer>();
			
			sb.append("<br />");
			sb.append("encrypting file...");
			//Veschluesselungs-Resultat wird in einem BigInteger[] gespeichert
			//start timer
			stopWatch.start();
			resultAr = encryptFile(data,e,n);
			stopWatch.stop();
			
			recordEncr = stopWatch.getTotalTimeMillis();
		    
			/*
			//add RSA-public key to keyList
			keyList.add(bitRange);
			//add recorded time for encryption to logList
			logList.add(recordEncr);
			
			
			if(count == 0)
			{
				oldFile = fileName;
				fileBuilderEncr.append("BitRange");
    			fileBuilderEncr.append(";");
    			fileBuilderEncr.append("Execution Time (ms)");
    			fileBuilderEncr.append("\n");
    			
    			//log Data and Write to File
				fileBuilderEncr.append(bitRange);
				fileBuilderEncr.append(";");
				fileBuilderEncr.append(recordEncr);
				fileBuilderEncr.append("\n");
    			count++;
    		}
			else if(count >= 1 && (oldFile.equals(fileName) == true))
			{
				count++;
				//log Data and Write to File
				fileBuilderEncr.append(bitRange);
				fileBuilderEncr.append(";");
				fileBuilderEncr.append(recordEncr);
				fileBuilderEncr.append("\n");
			}
			else if(count >= 1 && (oldFile.equals(fileName) == false))
			{
				count = 0;
				count++;
				oldFile = fileName;
				
				logList.clear();
				keyList.clear();	
				fileBuilderEncr.delete(0, fileBuilderEncr.length());
				
				fileBuilderEncr.append("BitRange");
    			fileBuilderEncr.append(";");
    			fileBuilderEncr.append("Execution Time (ms)");
    			fileBuilderEncr.append("\n");
    			
    			//log Data and Write to File
				fileBuilderEncr.append(bitRange);
				fileBuilderEncr.append(";");
				fileBuilderEncr.append(recordEncr);
				fileBuilderEncr.append("\n");
			}
			
			byte[] result = fileBuilderEncr.toString().getBytes();
			
			fos = new FileOutputStream(path.toString() + "_" +"LogEnryption.xls");
			fos.write(result);
			fos.close();*/
			
			sb.append("<br />");
			sb.append("File: " + "<font size=\"3\" color=\"red\">" + fileName + "</font>");
			sb.append(" succcessfully encrypted!");
			return sb.toString();
		}
		catch(Exception ex)
		{
			System.out.print(ex.getMessage());
		}
		return "No File to encrypt!";
	}
	
    @RequestMapping(value = "/startDecrypt/**", produces = MediaType.ALL_VALUE)
    @ResponseBody
    public String decryptFileREST(HttpServletRequest request)
    {
            StringBuilder sb = new StringBuilder();
            try
            {
            		//get Path for Decryption
                    String restOfURL = (String)request.getAttribute(
                                    HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE);

                    String uri  = "/startDecrypt";

                    int posOfFile = restOfURL.lastIndexOf(uri);
                    decryptPath = restOfURL.substring(posOfFile+uri.length());

                	stopWatch = new StopWatch("Monitor-Decryption");
        			logList = new ArrayList<Double>();
        			keyList = new ArrayList<Integer>();
                
        			sb.append("<br />");
                    sb.append("decrypting file...\n");
                    //Entschluesselungs-Resultat wird in einem byte[] gespeichert 
                    //und anschließend mithilfe des FileOutputStreams in eine neues-File geschrieben
                    stopWatch.start();
                    decryptedResultAr = decryptFile(resultAr,decryptKey,n,phi);
                    stopWatch.stop();
                   
                    fos = new FileOutputStream(decryptPath + "file_decrypted."+fileDataType);
                    fos.write(decryptedResultAr);
                    fos.close();
                    
                    recordDecr = stopWatch.getTotalTimeMillis();
        		    /*
        			//add RSA-public key to keyList
        			keyList.add(bitRange);
        			//add recorded time for encryption to logList
        			logList.add(recordDecr);
        			
        			if(countDecr == 0)
        			{
        				oldFileDecr = fileName;
        				fileBuilderDecr.append("BitRange");
        				fileBuilderDecr.append(";");
            			fileBuilderDecr.append("Execution Time (ms)");
            			fileBuilderDecr.append("\n");
            			
            			//log Data and Write to File
        				fileBuilderDecr.append(bitRange);
        				fileBuilderDecr.append(";");
        				fileBuilderDecr.append(recordDecr);
        				fileBuilderDecr.append("\n");
            			countDecr++;
            		}
        			else if(countDecr >= 1 && (oldFileDecr.equals(fileName) == true))
        			{
        				countDecr++;
        				//log Data and Write to File
        				fileBuilderDecr.append(bitRange);
        				fileBuilderDecr.append(";");
        				fileBuilderDecr.append(recordDecr);
        				fileBuilderDecr.append("\n");
        			}
        			else if(countDecr >= 1 && (oldFileDecr.equals(fileName) == false))
        			{
        				countDecr = 0;
        				countDecr++;
        				oldFileDecr = fileName;
        				
        				logList.clear();
        				keyList.clear();	
        				fileBuilderDecr.delete(0, fileBuilderDecr.length());
        				
        				fileBuilderDecr.append("BitRange");
            			fileBuilderDecr.append(";");
            			fileBuilderDecr.append("Execution Time (ms)");
            			fileBuilderDecr.append("\n");
            			
            			//log Data and Write to File
        				fileBuilderDecr.append(bitRange);
        				fileBuilderDecr.append(";");
        				fileBuilderDecr.append(recordDecr);
        				fileBuilderDecr.append("\n");
        			}
        			
        			byte[] result = fileBuilderDecr.toString().getBytes();
        			fosDecr = new FileOutputStream(path.toString() + "_" +"LogDecryption.xls");
        			fosDecr.write(result);
        			fosDecr.close();*/
                    
                    sb.append("<br />");
                    sb.append("File: " + "<font size=\"3\" color=\"red\">" + fileName + "</font>");
                    sb.append(" succcessfully decrypted!");
                    sb.append("<br />");
                    sb.append("<br />");
                    if(decryptPath.length() > 0)
                    {
                            sb.append("It's located in: " + decryptPath);
                            sb.append("<br />");
                            sb.append("Length of File: " + decryptedResultAr.length + " Byte");
                            sb.append("<br />");
                            sb.append("RSA-public key bit-range: " + bitRange);
                    }
                    else
                    {
                            sb.append("Error! No path stated in the URI!");
                    }
                    return sb.toString();
            }
            catch(Exception ex)
            {
                    System.out.println(ex.getMessage());
            }
            return "Error! Nothing to decrypt/ File-Path is wrong!";
    }

	
	//Verschluesselung
	public static BigInteger[] encryptFile(byte[] byteArray,BigInteger enKey, BigInteger n)
	{
		//Variablen-Deklaration
		int length = byteArray.length;
		BigInteger bigValue = new BigInteger("256");
		
		//Arrays fuer den Verschluesselungs-Vorgang
		BigInteger[] tempArray = new BigInteger[length];
		BigInteger[] resultEncryption = new BigInteger[length];
		
		for(int i=0; i<length; i++)
		{
			tempArray[i] = BigInteger.valueOf(byteArray[i]);
		}
		
		int i=0;
		for(BigInteger b : tempArray)
		{
			//Werte die kleiner als 0 sind, d.h. negative Werte (z.B. Umlaute im Text)
			//werden mit dem Wert "256" addiert, um diesen positiv zu machen
			//dieser Schritt wird benoetigt um richtig rechnen zu koennen,
			//da ansonsten mit negativen Werten gerechnet wird.
 			if(b.compareTo(BigInteger.ZERO)==-1)
			{
				b = b.add(bigValue);
			}
			//Verschluesselung nach RSA
			resultEncryption[i] = b.modPow(enKey,n);
			i++;
		}
		
		return resultEncryption;
		
	}
	
	//Entschluesselung
	public static byte[] decryptFile(BigInteger[] resultEncryption,BigInteger deKey,BigInteger n, BigInteger phi)
	{
		//Variablen-Deklaration
		int length = resultEncryption.length;
		BigInteger compareBig = new BigInteger("128");
	
		//Arrays fuer den Entschluesselungs-Vorgang
		BigInteger[] tempArray = new BigInteger[length];
		byte[] decryptionResult = new byte[length];
		
		//Abfrage ob der private-key < 0 ist,
		//falls ja -> wird phi(n) dazu addiert
		//um den private-key positiv zu machen
		if(deKey.compareTo(BigInteger.ZERO)==-1)
		{
			deKey = deKey.add(phi);
		}
		
		//Entschluesselung nach RSA
		int x=0;
		for(BigInteger b : resultEncryption)
		{
			tempArray[x] = b.modPow(deKey,n);
			x++;
		}
		
		for(int i=0; i<length; i++)
		{
			//Diese Abfrage ist besonders wichtig, 
			//da beim Verschluesselungs-Vorgang der Wert "256" dazu gezaehlt wurde
			//um mit positiven Werten rechnen zu koennen.
			//Da aber diese Werte großer als "127" sind, koennen diese nicht in ein byte[] geschrieben werden
			//daher wird der Wert wieder subtrahiert -> somit befindet man sich wieder im Wertebereich -128..127
			if(tempArray[i].compareTo(compareBig)==1)
			{
				tempArray[i]=tempArray[i].subtract(BigInteger.valueOf(256));
			}
			decryptionResult[i] = tempArray[i].byteValue();
		}
		
		return decryptionResult;
	}
		
}
	
