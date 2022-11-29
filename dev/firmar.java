
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.lang.*;


public class firmar {
    public static void main(String[] args) throws Exception {

    if(args.length!=1){
      System.out.println ("Error, numero de argumentos erroneo");
      System.exit(0);
    }

    String archivo = args[0];

	FileInputStream fmensaje   = new FileInputStream("/home/pedro-seg/Descargas/"+archivo);

    String provider         = "SunJCE";
    String algoritmo        =  "MD5withRSA";
    String algoritmo_base   =  "RSA";
    int    longitud_clave   =  2048;
    int    longbloque;
    byte   bloque[]         = new byte[1024];
    long   filesize         = 0;

    // Crea generador de claves

	KeyPairGenerator keyPairGen;
	keyPairGen = KeyPairGenerator.getInstance(algoritmo_base);

	// Crea generador de claves

    keyPairGen.initialize(longitud_clave);

	// Generamos un par de claves (publica y privada)
    KeyPair     keypair    = keyPairGen.genKeyPair();
    PrivateKey  privateKey = keypair.getPrivate();
    PublicKey   publicKey  = keypair.getPublic();

	/* Visualizar pareja claves */

    System.out.println("*** CLAVES PRIVADA ***");	System.out.println(privateKey);
    System.out.println("*** CLAVES PUBLICA ***");	System.out.println(publicKey);

    System.out.println("*** FIRMA    ***************************** ");

    // Creamos un objeto para firmar/verificar

    Signature signer = Signature.getInstance(algoritmo);

    // Inicializamos el objeto para firmar
    signer.initSign(privateKey);

	// Para firmar primero pasamos el hash al mensaje (metodo "update")
      // y despues firmamos el hash (metodo sign).

      byte[] firma = null;

      while ((longbloque = fmensaje.read(bloque)) > 0) {
        	filesize = filesize + longbloque;
    		signer.update(bloque,0,longbloque);
      }

	firma = signer.sign();

	double  v = firma.length;

	System.out.println("*** Fin Firma. La firma es: ");
	for (int i=0; i<firma.length; i++)
		System.out.print(firma[i] + " ");
	System.out.println();

	fmensaje.close();

	/*******************************************************************
	 *       Verificacion
	 ******************************************************************/
	System.out.println("*** VERIFICACION ***************************** ");

	FileInputStream fmensajeV   = new FileInputStream("/home/pedro-seg/Descargas/indice.jpeg");

	byte[] privateBytes = privateKey.getEncoded();
	byte[] publicBytes  = publicKey.getEncoded();

	//
	System.out.println("Longitud Privada = " + privateBytes.length);
	System.out.println("Longitud Publica = " + publicBytes.length);

	// Creamos un objeto para verificar
	Signature verifier=Signature.getInstance(algoritmo);

	//**** Para verificar usamos la clave Publica *******
	// (por defecto las claves publicas se almacenan en formato X.509)

	EncodedKeySpec keySpec;
	if (publicKey.getFormat().equals("X.509"))
		keySpec = new X509EncodedKeySpec (publicBytes);
	else
		keySpec = new PKCS8EncodedKeySpec(publicBytes);

    KeyFactory keyFactory = KeyFactory.getInstance(algoritmo_base);
    PublicKey  publicKey2 = keyFactory.generatePublic(keySpec);


	// Inicializamos el objeto

    verifier.initVerify(publicKey2);

    while ((longbloque = fmensajeV.read(bloque)) > 0) {
        filesize = filesize + longbloque;
    	verifier.update(bloque,0,longbloque);
    }

	boolean resultado = false;

	resultado = verifier.verify(firma);

	if (resultado == true)
	    System.out.print("Firma CORRECTA\n");
	else
	    System.out.print("Firma NO correcta\n");

	fmensajeV.close();

    }
}
