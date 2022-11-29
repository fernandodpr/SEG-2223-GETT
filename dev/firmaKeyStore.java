import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
//
//

public class firmaKeyStore {

    public static void main(String[] args) throws Exception {

      String directorioRaiz = "/home/pedro-seg/";
    FileInputStream fmensaje   = new    FileInputStream(directorioRaiz + "Descargas/indice2.jpeg");

    String 		provider         = "SunJCE";
    String 		algoritmo        = "SHA1withDSA";
    int    		longbloque;
    byte   		bloque[]         = new byte[1024];
    long   		filesize         = 0;

    // Variables para el KeyStore

	KeyStore    ks;
	char[]      ks_password  	= "1234".toCharArray();
	char[]      key_password 	= "1234".toCharArray();
	String		ks_file			= directorioRaiz + "KeyStore_Cliente1.jce";
    String		entry_alias		= "Client";

	System.out.println("******************************************* ");
	System.out.println("*               FIRMA                     * ");
	System.out.println("******************************************* ");

	// Obtener la clave privada del keystore

	ks = KeyStore.getInstance("JCEKS");

	ks.load(new FileInputStream(ks_file),  ks_password);

	KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
 	      		   						ks.getEntry(entry_alias,
                                        new KeyStore.PasswordProtection(key_password));

    PrivateKey privateKey = pkEntry.getPrivateKey();

    // Visualizar clave privada

    System.out.println("*** CLAVE PRIVADA ***");
	System.out.println("Algoritmo de Firma (sin el Hash): " + privateKey.getAlgorithm());
	System.out.println(privateKey);

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

	System.out.println("*** FIRMA: ****");
	for (int i=0; i<firma.length; i++)

		System.out.print(firma[i] + " ");
	System.out.println();
	System.out.println();

	fmensaje.close();

	/*******************************************************************
	 *       Verificacion
	 ******************************************************************/
	System.out.println("************************************* ");
	System.out.println("        VERIFICACION                  ");
	System.out.println("************************************* ");

	FileInputStream fmensajeV   = new FileInputStream(directorioRaiz + "Descargas/indice2.jpeg");


    // Obtener la clave publica del keystore
    PublicKey   publicKey  = ks.getCertificate(entry_alias).getPublicKey();

    System.out.println("*** CLAVE PUBLICA ***");
    System.out.println(publicKey);

    // Obtener el usuario del Certificado tomado del KeyStore.
    //   Hay que traducir el formato de certificado del formato del keyStore
    //	 al formato X.509. Para eso se usa un CertificateFactory.

    byte []   certificadoRaw  = ks.getCertificate(entry_alias).getEncoded();
    ByteArrayInputStream inStream = null;
    inStream = new ByteArrayInputStream(certificadoRaw);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

    StringBuilder certint = new StringBuilder();
        for (byte temp : cert.getPublicKey().getEncoded()) {
            certint.append(String.format("%02x", temp));
        }
    System.out.println ("CERTIFICADO: " +
				"\n -- Algoritmo Firma .... = " + cert.getSigAlgName() +
				"\n -- Usuario ............ = " + cert.getIssuerX500Principal() +
				"\n -- Parametros Algoritmo = " + cert.getSigAlgParams() +
				"\n -- Algoritmo de la PK.. = " + cert.getPublicKey().getAlgorithm() +
				"\n -- Formato  ........... = " + cert.getPublicKey().getFormat() +
				"\n -- Codificacion ....... = " + certint.toString()
    		);

	// Creamos un objeto para verificar, pasandole el algoritmo leido del certificado.

	Signature verifier=Signature.getInstance(cert.getSigAlgName());

    // Inicializamos el objeto para verificar

    verifier.initVerify(publicKey);

    while ((longbloque = fmensajeV.read(bloque)) > 0) {
        filesize = filesize + longbloque;
    	verifier.update(bloque,0,longbloque);
    }

	boolean resultado = false;

	resultado = verifier.verify(firma);

	System.out.println();
	if (resultado == true)
	    System.out.print("Verificacion correcta de la Firma");
	else
		System.out.print("Fallo de verificacion de firma");

	fmensajeV.close();

    }
}
