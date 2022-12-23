package ServidorEjemplo;
/*
 * @(#)ClassFileServer.java	1.5 01/05/10
 *
 * Copyright 1994-2004 Sun Microsystems, Inc. All Rights Reserved. 
 *
 * Redistribution and use in source and binary forms, with or 
 * without modification, are permitted provided that the following 
 * conditions are met: 
 * 
 * -Redistribution of source code must retain the above copyright 
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistribution in binary form must reproduce the above copyright 
 * notice, this list of conditions and the following disclaimer in 
 * the documentation and/or other materials provided with the 
 * distribution. 
 * 
 * Neither the name of Sun Microsystems, Inc. or the names of 
 * contributors may be used to endorse or promote products derived 
 * from this software without specific prior written permission.
 * 
 * This software is provided "AS IS," without a warranty of any 
 * kind. ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND 
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE HEREBY 
 * EXCLUDED. SUN MICROSYSTEMS, INC. ("SUN") AND ITS LICENSORS SHALL 
 * NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT 
 * OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS 
 * DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR 
 * ANY LOST REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, 
 * SPECIAL, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER 
 * CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY, ARISING OUT OF 
 * THE USE OF OR INABILITY TO USE THIS SOFTWARE, EVEN IF SUN HAS 
 * BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. 
 * 
 * You acknowledge that this software is not designed, licensed or 
 * intended for use in the design, construction, operation or 
 * maintenance of any nuclear facility. 
 */

import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.EnumSet;

import javax.net.*;
import javax.net.ssl.*;
import javax.security.cert.X509Certificate;

/* ClassFileServer.java -- a simple file server that can server
 * Http get request in both clear and secure channel
 *
 * The ClassFileServer implements a ClassServer that
 * reads files from the file system. See the
 * doc for the "Main" method for how to run this
 * server.
 */

public class ClassFileServer extends ClassServer {

    private String docroot;

    private static int      DefaultServerPort = 9001;
	private static String 	raizMios     = "C:/Escuela/SEG/Laboratorio/servidor/";

    /**
     * Constructs a ClassFileServer.
     *
     * @param path the path where the server locates files
     */
    public ClassFileServer(ServerSocket ss, String docroot) throws IOException
    {
	super(ss);
	this.docroot = docroot;
    }

    /**
     * Returns an array of bytes containing the bytes for
     * the file represented by the argument <b>path</b>.
     *
     * @return the bytes for the file
     * @exception FileNotFoundException if the file corresponding
     * to <b>path</b> could not be loaded.
     */
    public byte[] getBytes(String path)
	throws IOException
    {
	System.out.println("reading: " + path);
	File f = new File(docroot + File.separator + path);
	int length = (int)(f.length());
	if (length == 0) {
	    throw new IOException("File length is zero: " + path);
	} else {
	    FileInputStream fin = new FileInputStream(f);
	    DataInputStream in = new DataInputStream(fin);

	    byte[] bytecodes = new byte[length];
	    in.readFully(bytecodes);
	    return bytecodes;
	}
    }

    /**
     * Main method to create the class server that reads
     * files. This takes two command line arguments, the
     * port on which the server accepts requests and the
     * root of the path. To start up the server: <br><br>
     *
     * <code>   java ClassFileServer <port> <path>
     * </code><br><br>
     *
     * <code>   new ClassFileServer(port, docroot);
     * </code>
     */
    
    public static void main(String args[])
    {
   	String[]   cipherSuites = null;
        
	System.out.println(
	    "USAGE: java ClassFileServer port docroot [TLS [true]]");
	System.out.println("");
	System.out.println(
	    "If the third argument is TLS, it will start as\n" +
	    "a TLS/SSL file server, otherwise, it will be\n" +
	    "an ordinary file server. \n" +
	    "If the fourth argument is true,it will require\n" +
	    "client authentication as well.");

	int port = DefaultServerPort;
	String docroot = "";

	
	//  Definir valores para los almacenes necesarios
	
	definirAlmacenesServidor();
	
	//  Definir las variables para establecer OCSP stapling
    	//  2 metodos: Probar primero con el metodo 1 y luego pasarse al metodo 2
	
	definirRevocacionOCSPStapling_Metodo1();
	//definirRevocacionOCSPStapling_Metodo2();
	
	//  Chequear argumentos
	
	if (args.length >= 1) {
	    port = Integer.parseInt(args[0]);
	}

	if (args.length >= 2) {
	    docroot = args[1];
	}
	String type = "PlainSocket";
	if (args.length >= 3) {
	    type = args[2];
	}
	
	try {
	    ServerSocketFactory ssf =
	    		ClassFileServer.getServerSocketFactory(type);
	    
	    ServerSocket ss = ssf.createServerSocket(port);
	    
	    // Ver los protocolos
    	System.out.println ("*****************************************************");
    	System.out.println ("*  Protocolos soportados en Servidor                 ");
    	System.out.println ("*****************************************************");

	 	String[] protocols = ((SSLServerSocket)ss).getEnabledProtocols();
	 	for (int i=0; i<protocols.length; i++) 
	    	System.out.println (protocols[i]);	    
    		
    	System.out.println ("*****************************************************");
    	System.out.println ("*    Protocolo forzados                               ");
    	System.out.println ("*****************************************************");
	 	
	 	String[] protocolsNew = {"TLSv1.3"};
	 	
	 	((SSLServerSocket)ss).setEnabledProtocols(protocolsNew);
	 	
	 	//  volvemos a mostrarlos
	 	protocols = ((SSLServerSocket)ss).getEnabledProtocols();
	 	for (int i=0; i<protocols.length; i++) 
	    	System.out.println (protocols[i]);	    
    	
	    
	    if (args.length >= 4 && args[3].equals("true")) {
	    
	    	System.out.println ("*****************************************************");
	    	System.out.println ("*  Server inicializado CON Autenticacion de cliente  ");
	    	System.out.println ("*****************************************************");

	    	// Ver Suites disponibles en Servidor
	    	
	    	System.out.println ("*****************************************************");
	    	System.out.println ("*         CypherSuites Disponibles en SERVIDOR       ");
	    	System.out.println ("*****************************************************");
	    	
		 	cipherSuites = ((SSLServerSocket)ss).getSupportedCipherSuites();
		 	for (int i=0; i<cipherSuites.length; i++) 
		    	System.out.println (i + "--" + cipherSuites[i]);	    
	    	
		 	//  Definir suites Habilitadas en server
		 	
		 	((SSLServerSocket)ss).setNeedClientAuth(true);
		 	
	        String[]   cipherSuitesHabilitadas = {"TLS_RSA_WITH_NULL_SHA256",
	        		                              "TLS_ECDHE_RSA_WITH_NULL_SHA",
	        		                               //TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	        		                              //"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	        		                              };

	        if (false) // cambiar a true para cambiarlas
	        	((SSLServerSocket)ss).setEnabledCipherSuites(cipherSuitesHabilitadas);
	        
	    	System.out.println ("*****************************************************");
	    	System.out.println ("*         CypherSuites Habilitadas en SERVIDOR       ");
	    	System.out.println ("*****************************************************");
	    
		 	cipherSuites = ((SSLServerSocket)ss).getEnabledCipherSuites();
		 	for (int i=0; i<cipherSuites.length; i++) 
		    	System.out.println (i + "--" + cipherSuites[i]);	    
	    	
	    }
	    
	    new ClassFileServer(ss, docroot);

	} catch (IOException e) {
	    System.out.println("Unable to start ClassServer: " +
			       e.getMessage());
	    e.printStackTrace();
	}
    }

    private static ServerSocketFactory getServerSocketFactory(String type) {
	
    if (type.equals("TLS")) {
    	
    	
	    SSLServerSocketFactory ssf = null;

	    try {
	    	
	    	definirRevocacionOCSPStapling();
	    	
  			/********************************************************************************
			*   Construir un contexto, pasandole el KeyManager y y TrustManager 
			*   Al TrustManager se le incorpora el chequeo de certificados revocados por Ocsp. 
			*   
			*   NOTA: Esto seria necesario para la verificacion de no-revocacion OCSP
			*   del certificado del cliente
			*   
			********************************************************************************/
	    	// set up key manager to do server authentication

			char[] passphrase = "123456".toCharArray();
			
			// --- Trust manager.
			
			//  1. Crear PKIXRevocationChecker
			CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
			PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
			rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
			rc.setOcspResponder(new URI("http://192.168.0.50:9080"));  // Aqui poner la ip y puerto donde se haya lanzado el OCSP Responder


			//   2. Crear el truststore 
			
			KeyStore ts = KeyStore.getInstance("JCEKS");
			ts.load(new FileInputStream(raizMios + "TrustStoreServidor.jce"), "123456".toCharArray());
			
			//  3. Crear los parametros PKIX y el PKIXRevocationChecker
			
			PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ts, new X509CertSelector());
			//pkixParams.addCertPathChecker(rc);
			pkixParams.setRevocationEnabled(true); // habilitar la revocacion (por si acaso)
			
			//
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(new CertPathTrustManagerParameters(pkixParams));
			
	    	// set up key manager to do server authentication

			KeyManagerFactory kmf;
			KeyStore ks;
	
			// --- Key manager 

			kmf = KeyManagerFactory.getInstance("SunX509");
			ks = KeyStore.getInstance("JCEKS");	
			//ks.load(new FileInputStream(raizMios + "KeyStoreServidor.jce"), passphrase);
			ks.load(new FileInputStream(raizMios + "serverKeystore.jceks"), passphrase);
			kmf.init(ks, passphrase);
		
			// Crear el contexto
			SSLContext ctx;
			ctx = SSLContext.getInstance("TLS");		
			ctx.init(kmf.getKeyManagers(),  
					 null,//tmf.getTrustManagers(), --solo si se hace el OCSP del certificado del cliente
					 null);
			
			ssf = ctx.getServerSocketFactory();
			return ssf;
			
	    } catch (Exception e) {
					e.printStackTrace();
				    }
	} else {
	    return ServerSocketFactory.getDefault();
	}
	return null;
    }




    private static void definirAlmacenesServidor()
	{

		// Almacen de claves
		
		System.setProperty("javax.net.ssl.keyStore",         raizMios + "serverKeystore.jceks");
		System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", "32004");

		// Almacen de confianza
		System.setProperty("javax.net.ssl.trustStore",          raizMios + "TrustStoreServidor.jce");		
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "123456");

	}

    private static void definirRevocacionOCSPStapling_Metodo1()
	{
    	//
    	//  Metodo 1: Con URL en el campo AIA del certificado del servidor
    	//
    	    	
	    	System.setProperty("jdk.tls.server.enableStatusRequestExtension", "true");
		System.setProperty("jdk.tls.stapling.responderOverride","false");

	//  Cambios en el certificado del servidor:
	//      En la seccion [server_ext] del fichero root-ca.conf), añadir ñla siguiente linea
	//  
        //      authorityInfoAccess= OCSP; URI:http://localhost:9080
	//
        //   Luego volver a firmar el certificado e importarlo al keyStore del server

	}

    private static void definirRevocacionOCSPStapling_Metodo2()
	{    		    
    	//
    	//  Metodo 2: Con URL en el codigo java del server  (aqui)
    	//
    
    		System.setProperty("jdk.tls.server.enableStatusRequestExtension", "true");
	  	System.setProperty("jdk.tls.stapling.responderOverride","true");
		System.setProperty("jdk.tls.stapling.responderURI", "http://192.168.0.50:9080");		
		System.setProperty("jdk.tls.stapling.ignoreExtensions", "true");
	}

}