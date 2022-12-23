package ClienteWeb;
/*
 * @(#)SSLSocketClientWithClientAuth.java	1.5 01/05/10
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


import java.net.*;
import java.io.*;

import javax.net.ssl.*;

import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.EnumSet;

/*
 * This example shows how to set up a key manager to do client
 * authentication if required by server.
 *
 * This program assumes that the client is not inside a firewall.
 * The application can be modified to connect to a server outside
 * the firewall by following SSLSocketClientWithTunneling.java.
 */
public class SSLSocketClientWithClientAuthEjemplo {


	private static String 	raizMios  = "C:/Escuela/SEG/Laboratorio/cliente/";
    
	
    public static void main(String[] args) throws Exception {
	
    	String host = null;
    	int port = -1;
    	String path = null;
    	String[]   cipherSuitesDisponibles = null;
	
	
	for (int i = 0; i < args.length; i++)
	    System.out.println(args[i]);

	if (args.length < 3) {
	    System.out.println(
		"USAGE: java SSLSocketClientWithClientAuth " +
		"host port requestedfilepath");
	    System.exit(-1);
	}

	try {
	    host = args[0];
	    port = Integer.parseInt(args[1]);
	    path = args[2];
	} catch (IllegalArgumentException e) {
	     System.out.println("USAGE: java SSLSocketClientWithClientAuth " +
		 "host port requestedfilepath");
	     System.exit(-1);
	}

	try {

		definirAlmacenesCliente();
		definirRevocacionOCSPStapling();
		//definirRevocacionOCSP();
	
		/*
	     * Set up a key manager for client authentication
	     * if asked by the server.  Use the implementation's
	     * default TrustStore and secureRandom routines.
	     */
	    SSLSocketFactory factory = null;
	    
		try {
			SSLContext ctx;
			KeyManagerFactory kmf;
			KeyStore ks;
			char[] passphrase = "123456".toCharArray();

			/********************************************************************************
			* Construir un contexto, pasandole el KeyManager y y TrustManager 
			* Al TrustManager se le incorpora el chequeo de certificados revocados por Ocsp. 
			*   
			********************************************************************************/
			// --- Trust manager.
			
			//  1. Crear PKIXRevocationChecker

			CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
			PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
			rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
			rc.setOcspResponder(new URI("http://192.168.0.50:9080"));  // Aqui poner la ip y puerto donde se haya lanzado el OCSP Responder

			//   2. Crear el truststore 
			
			KeyStore ts = KeyStore.getInstance("JCEKS");
			ts.load(new FileInputStream(raizMios + "TrustStoreCliente.jce"), passphrase);
			
			//  3. Crear los parametros PKIX y el PKIXRevocationChecker
			
			PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ts, new X509CertSelector());
			pkixParams.addCertPathChecker(rc);
			pkixParams.setRevocationEnabled(false); // habilitar la revocacion (por si acaso)
			
			//
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(new CertPathTrustManagerParameters(pkixParams));
			

			// --- Key manager 
			
			kmf = KeyManagerFactory.getInstance("SunX509");
			ks = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(raizMios + "KeyStoreCliente.jce"), passphrase);
			kmf.init(ks, passphrase);
			
			// Crear el contexto
			ctx = SSLContext.getInstance("TLS");		
			ctx.init(kmf.getKeyManagers(),  
					 tmf.getTrustManagers(), 
					 null);
	
			factory = ctx.getSocketFactory();
			        
			// Suites disponibles		
		
	    	 System.out.println ("*****************************************************");
	    	 System.out.println ("*         CypherSuites Disponibles en CLIENTE        ");
	    	 System.out.println ("*****************************************************");
	    	 
	         String[]cipherSuites = factory.getSupportedCipherSuites();
 	   	     for (int i=0; i<cipherSuites.length; i++) 
 	       		System.out.println (cipherSuites[i]);	    
 		   	    
 	   	     // Suites habilitadas por defecto
 	   	     
	    	 System.out.println ("*****************************************************");
	    	 System.out.println ("*         CypherSuites Habilitadas por defecto       ");
	    	 System.out.println ("*****************************************************");
	     	    
 	   	     String[] cipherSuitesDef = factory.getDefaultCipherSuites();
 	   	     for (int i=0; i<cipherSuitesDef.length; i++) 
 	       		 System.out.println (cipherSuitesDef[i]);
     
		} catch (Exception e) {
				throw new IOException(e.getMessage());}

	  SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
	 
	  // Ver los protocolos
	  
  	  System.out.println ("*****************************************************");
  	  System.out.println ("*  Protocolos soportados en Cliente                 ");
  	  System.out.println ("*****************************************************");

	  String[] protocols = socket.getEnabledProtocols();
	  for (int i=0; i<protocols.length; i++) 
	    	System.out.println (protocols[i]);	    
  		
  	  System.out.println ("*****************************************************");
  	  System.out.println ("*    Protocolo forzado                               ");
  	  System.out.println ("*****************************************************");
	 	
	  String[] protocolsNew = {"TLSv1.3"};	  
	
	  socket.setEnabledProtocols(protocolsNew);


	  System.out.println ("*****************************************************");
	  System.out.println ("*         CypherSuites  Disponibles (Factory)        ");
	  System.out.println ("*****************************************************");
 
      cipherSuitesDisponibles = factory.getSupportedCipherSuites();
      for (int i=0; i<cipherSuitesDisponibles.length; i++) 
 		  System.out.println (cipherSuitesDisponibles[i]);	    
      
      // Habilitar las suites deseadas
      
      String[]   cipherSuitesHabilitadas = {//"TLS_RSA_WITH_NULL_SHA256",
    		                               //"TLS_ECDHE_RSA_WITH_NULL_SHA",
							    		  "TLS_AES_128_GCM_SHA256",
							    		  //"TLS_AES_256_GCM_SHA384",
							    		  //"TLS_CHACHA20_POLY1305_SHA256",
							    		  //"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
							    		  //"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
							    		  //"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
							    		  //"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
							    		  //"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
							    		  //"TLS_RSA_WITH_AES_256_GCM_SHA384",
							    		  //"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
							    		  //"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
							    		  //"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
							    		  //"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
							    		  //"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
							    		  //"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
							    		  //"TLS_RSA_WITH_AES_128_GCM_SHA256",
							    		  "TLS_RSA_WITH_AES_128_CBC_SHA256",
							    		  "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
							    		  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
							    		  "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
							    		  "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
							    		  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
							    		  "TLS_RSA_WITH_AES_128_GCM_SHA256",
							    		  "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
							    		  "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
							    		  "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
  		  
    		                               };	 
     if (true)
    	 socket.setEnabledCipherSuites(cipherSuitesHabilitadas);
 	 
	 System.out.println ("*****************************************************");
	 System.out.println ("*         CypherSuites Habilitadas en socket         ");
	 System.out.println ("*****************************************************");
     
 	 String[] cipherSuitesHabilSocket = socket.getEnabledCipherSuites();
  	 for (int i=0; i<cipherSuitesHabilSocket.length; i++) 
 	       		System.out.println (cipherSuitesHabilSocket[i]);

     socket.getSSLParameters().getUseCipherSuitesOrder();


	    /*
	     * send http request
	     *
	     * See SSLSocketClient.java for more information about why
	     * there is a forced handshake here when using PrintWriters.
	     */
	    
	    
	    System.out.println ("Comienzo SSL Handshake");
	    socket.startHandshake();	    
	    System.out.println ("Fin SSL Handshake");
	    //String s = socket.getHandshakeSession().getCipherSuite();
	    System.out.println ("*****************" + socket.getSession());
	   
	

	    PrintWriter out = new PrintWriter(
				  new BufferedWriter(
				  new OutputStreamWriter(
     				  socket.getOutputStream())));
	    out.println("GET /" + path + " HTTP/1.1");
	    out.println();
	    out.flush();

	    /*
	     * Make sure there were no surprises
	     */
	    if (out.checkError())
		System.out.println(
		    "SSLSocketClient: java.io.PrintWriter error");

	    /* read response */
	    BufferedReader in = new BufferedReader(
				    new InputStreamReader(
				    socket.getInputStream()));

	    String inputLine;

	    while ((inputLine = in.readLine()) != null)
		System.out.println(inputLine);

	    in.close();
	    out.close();
	    socket.close();

	} catch (Exception e) {
	    e.printStackTrace();
	}
    }
    

	
	
    private static void definirAlmacenesCliente()
	{
		String 	raizMios     = "C:/Escuela/SEG/Laboratorio/cliente/";

		// Almacen de claves
		
		System.setProperty("javax.net.ssl.keyStore",            raizMios + "KeyStoreCliente.jce");
		System.setProperty("javax.net.ssl.keyStoreType",       "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword",   "123456");

		// Almacen de confianza
		
		System.setProperty("javax.net.ssl.trustStore",          raizMios + "TrustStoreCliente.jce");		
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "123456");

	}
    
    private static void definirRevocacionOCSP()
	{

		// Almacen de claves
		
		System.setProperty("com.sun.net.ssl.checkRevocation",        "true");
		System.setProperty("ocsp.enable",                            "true");

	}
    
    private static void definirRevocacionOCSPStapling()
	{

		// Almacen de claves
		
		System.setProperty("jdk.tls.client.enableStatusRequestExtension",   "true");
		System.setProperty("com.sun.net.ssl.checkRevocation",        "true");
		System.setProperty("ocsp.enable",                            "false");

	}
}
