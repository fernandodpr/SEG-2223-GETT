/**********************************************************************
	 Nombre:
		Cifrar_Descifrar_Simetrico_IAIK_SunJCE_v1.0

	Descripcion:
		Codigo JAVA para cifrar y descifrar un fichero, usando cualquiera
		de los algoritmos de cifrado simetrico de los providers “SunJCE”, y “IAIK”
		tanto de cifrado en bloque como de cifrado en flujo.

	Notas de uso:
                    1. No valido para cifrado PBE
                    2. Permite medir el tiempo y velocidad de cifrado.
                    3. Requiere dar la ubicacion concreta de lso ficheros

	Fecha:
		28/11/2012
	Autor:
               	Francisco J. Fernandez Masaguer
		ETSI TELECOMUNACION VIGO
		Departamento Ingenieria Telematica
      	email: francisco.fernandez@det.uvigo.es

               Asignatura:
		SEGURIDAD.  3º GETT.   Curso  2012/2013.

***********************************************************/
package practica1;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.AlgorithmParameters;

// IAIK librerias
import iaik.security.provider.IAIK;
import iaik.utils.CryptoUtils;

public class CifradoSimetrico {

	public static void main(String[] args) throws Exception {

	String provider         = "SunJCE";

	FileInputStream  ftextoclaro      = new FileInputStream (".../textoclaro");
	FileOutputStream ftextocifrado = new FileOutputStream(".../textocifrado");
	FileOutputStream fparametros   = new FileOutputStream(".../parametros");
	FileOutputStream fclave            = new FileOutputStream(".../fclaveks");
	FileInputStream  fclave_in        = new FileInputStream (".../fclaveks");
	BufferedWriter   fmedidas         = new BufferedWriter(new FileWriter(".../medidasCifrado"));

	byte   bloqueclaro[]    = new byte[2024];

        	byte   bloquecifrado[]  = new byte[2048];
        	String algoritmo        = "AES";
        	String transformacion   = "/CBC/PKCS5Padding";
        	int    longclave        = 128;
        	int    longbloque;
        	int    i;
        	double t, tbi,tbf;
        	double lf;              // longitud del fichero


        if (provider.equals("IAIK")) { IAIK.addAsProvider(); }  


        /************** Generar clave **********************/
        KeyGenerator  kgen     = KeyGenerator.getInstance(algoritmo);
        kgen.init(longclave);
        SecretKey     skey     = kgen.generateKey();

        byte[]        skey_raw      = skey.getEncoded();
        fclave.write(skey_raw);
        fclave.close();

        fclave_in.read(skey_raw);
        SecretKeySpec ks = new SecretKeySpec(skey_raw, algoritmo);


        //*******************************************************************
        //               Cifrar
        //*******************************************************************
        System.out.println("*** INICIO CIFRADO " + algoritmo + "-" + longclave + " ************");

        Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);

        cifrador.init(Cipher.ENCRYPT_MODE, ks);


        i = 0;
        t = 0;
        lf = 0;
        tbi = 0;
        tbf = 0;

        while ((longbloque = ftextoclaro.read(bloqueclaro)) > 0) {
               i++;

               lf = lf + longbloque;

               tbi = System.nanoTime();
               bloquecifrado = cifrador.update(bloqueclaro,0,longbloque);
               tbf = System.nanoTime();

               t = t + tbf - tbi;
               fmedidas.write("T iteracion " +  i  + " = " + (tbf-tbi) + " nanoseg \n");         

               ftextocifrado.write(bloquecifrado);
        }     

        // Hacer dofinal y medir su tiempo
        tbi = System.nanoTime();
        bloquecifrado = cifrador.doFinal();
        tbf = System.nanoTime();

        t = t + tbf - tbi;

        ftextocifrado.write(bloquecifrado);

        // Escribir resultados

        //System.out.println("Long. ultimo bloque" + bloquecifrado.length );
        System.out.println("*** FIN CIFRADO " + algoritmo + "-" + longclave + " Provider: " + provider);
        System.out.println("Bytes  cifrados = " + (int)lf );
        System.out.println("Tiempo cifrado  = " + t/1000000 + " mseg");
        System.out.println("Velocidad       = " + (lf*8*1000)/ t + " Mpbs");

        // Cerrar ficheros
 	    ftextocifrado.close();
        ftextoclaro.close();
        fmedidas.close();

        /*******************************************************************
        *  Obtener parametros del algoritmo y archivarlos
        *  
        *  NOTA: Para los cifradores en flujo no se ejecuta el lazo de  
        *        parametros porque no se necesitan. Ejemplo: RC4
        *******************************************************************/
        // System.out.println("Leer los parametros(IV,...) usados por el cifrador ..." );

        //AlgorithmParameters  paramxx =  cifrador.getParameters();

        if (provider.equals("SunJCE") &&
                ( algoritmo.equals("AES")                    ||
        		  algoritmo.equals("Blowfish")               ||
        		  algoritmo.equals("DES")                    ||
        		  algoritmo.equals("DESede")                 ||
        		  algoritmo.equals("DiffieHellman")          ||
        		  algoritmo.equals("OAEP")                   ||
        		  algoritmo.equals("PBEWithMD5AndDES")       ||
        		  algoritmo.equals("PBEWithMD5AndTripleDES") ||
        		  algoritmo.equals("PBEWithSHA1AndDESede")   ||
        		  algoritmo.equals("PBEWithSHA1AndRC2_40")   ||
        		  algoritmo.equals("RC2")
        		  )
            ||  (provider.equals("IAIK") && (! algoritmo.equals("RC4")))  )

        {
        		 AlgorithmParameters param = AlgorithmParameters.getInstance(algoritmo);        
        		 param =  cifrador.getParameters();

        		 System.out.println("Parametros del cifrado ..." + param.toString());
        		 byte[]  paramSerializados = param.getEncoded();
        		 fparametros.write(paramSerializados);
        		 fparametros.close();

        };


        //*****************************************************************************
        //					DESCIFRAR
        //*****************************************************************************
	FileInputStream  ftextocifrado2 = new FileInputStream (".../textocifrado");
	FileOutputStream ftextoclaro2   = new FileOutputStream(".../textoclaro2");
	FileInputStream  fparametros_in = new FileInputStream (".../parametros");

        byte bloquecifrado2[]  = new byte[1024];
        byte bloqueclaro2[]    = new byte[1048];

        System.out.println("*************** INICIO DESCIFRADO *****************" );

        Cipher descifrador = Cipher.getInstance(algoritmo + transformacion, provider);

        // Leer los parametros si el algoritmo soporta parametros
        if (provider.equals("SunJCE") &&
                ( algoritmo.equals("AES")                    ||
        		  algoritmo.equals("Blowfish")               ||
        		  algoritmo.equals("DES")                    ||
        		  algoritmo.equals("DESede")                 ||
        		  algoritmo.equals("DiffieHellman")          ||
        		  algoritmo.equals("OAEP")                   ||
        		  algoritmo.equals("PBEWithMD5AndDES")       ||
        		  algoritmo.equals("PBEWithMD5AndTripleDES") ||
        		  algoritmo.equals("PBEWithSHA1AndDESede")   ||
        		  algoritmo.equals("PBEWithSHA1AndRC2_40")   ||
        		  algoritmo.equals("RC2")
        		  )
        	 ||  (provider.equals("IAIK") && (! algoritmo.equals("RC4")))        			
   			 )

        {
            AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmo,provider);        
            byte[] paramSerializados = new byte[fparametros_in.available()];

            fparametros_in.read(paramSerializados);         
            params.init(paramSerializados);

            System.out.println("Parametros del descifrado ... = " + params.toString());

            descifrador.init(Cipher.DECRYPT_MODE, ks, params);
        }
        else
        {
        	descifrador.init(Cipher.DECRYPT_MODE, ks);
        }


        while ((longbloque = ftextocifrado2.read(bloquecifrado2)) > 0) {

              bloqueclaro2 = descifrador.update(bloquecifrado2,0,longbloque);

             //System.out.println("Longitud cifrado " + bloquecifrado.length );
             ftextoclaro2.write(bloqueclaro2);
        }

        bloqueclaro2 = descifrador.doFinal();
 	    ftextoclaro2.write(bloqueclaro2);

 	    ftextocifrado2.close();
        ftextoclaro2.close();

        System.out.println("*************** FIN DESCIFRADO *****************" );

	}
}
