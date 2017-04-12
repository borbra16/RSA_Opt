package rsa.example.controller;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

//Klasse fuer den Euklidischen Algorithmus
//und fuer den Erweiterten Euklidischen Algorithmus
public class EuklidAlgorithm
{
	public BigInteger[][] ggT(BigInteger a, BigInteger b)
	{
		//Variablen und Array Deklaration
		BigInteger rest = new BigInteger("0");
		BigInteger modRest = new BigInteger("0");
		BigInteger ggT = new BigInteger("0");
		BigInteger tempVar = new BigInteger("0");
		BigInteger[][] tempArray = null;
		int	listLength = 0;
	
		//Um den GGT von beliebig großen Zahlen berechnen zu koennen
		//wurde eine ArrayList gewaehlt
		List<BigInteger[]> rowList = new ArrayList<BigInteger[]>();
	
		//Berechnung des GGT
		while((a.mod(b))!= BigInteger.valueOf(0))
		{
			rest = (a.mod(b));
			modRest = a.divide(b);
		
			//hier wird jeweils eine Zeile ein weiteres Array erzeugt (jeweils die Spalten)
			//d.h. fuer [0] -> erzeugt man ein weiteres Array mit den Werten a,b,modRest und rest
			//so bekommt man ein dynamische Liste fuer belieb viele Zeilen.
			rowList.add(new BigInteger[]{a,b,modRest,rest});
			
			tempVar = a;
			a = b;
			b = rest;
			ggT = rest;
		}
		rest = a.mod(b);
		modRest = a.divide(b);
		
		rowList.add(new BigInteger[]{a,b,modRest,rest});
		
		listLength = rowList.size();
		
		tempArray = new BigInteger[listLength][4];
		
		//Hier werden Werte aus der Liste in ein BigInteger[][] geschrieben.
		for(int x=0; x<4; x++)
		{
			for(int g=0; g<rowList.size();g++)
			{
				tempArray[g][x] = rowList.get(g)[x];
			}
		}
		
		return tempArray;
		
	}
	
	//Methode fuer die Berechnung des Multiplikativen Inversen
	public BigInteger advancedEuklid(BigInteger[][] ggTArray)
	{
		BigInteger tempVar = new BigInteger("0");
		BigInteger x = new BigInteger("0");
		BigInteger y = new BigInteger("1");
		
		//Umsetzung der Berechung in der letzten Labor-EH
		for(int i=ggTArray.length-1; i>0; i--)
		{	
			tempVar = y;
			y = x.subtract(ggTArray[i-1][2].multiply(tempVar));
			x = tempVar;
		}
		
		return y;
	}
}
