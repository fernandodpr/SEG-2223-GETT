package ClienteWeb;

import java.net.*;
import java.io.*;

import javax.net.ssl.*;

/*
 * This example demostrates how to use a SSLSocket as client to
 * send a HTTP request and get response from an HTTPS server.
 * It assumes that the client is not behind a firewall
 */

public class ClienteSinAuth {	

	private static String 	raizMios = "C:/Users/Administrador/Documents/";
	private static String 	raiz     = "c:/comun/escuela/seguridad_bolonia/practica2013/servidor/";

	
    public static void main(String[] args) throws Exception {
	try {		

		definirKeyStores();
		//definirKeyStoresEjemploJSSE();
	    
	    SSLSocketFactory factory =
	    		(SSLSocketFactory)SSLSocketFactory.getDefault();

	    System.out.println ("Crear socket");
	    SSLSocket socket =
	    		(SSLSocket)factory.createSocket(args[0], Integer.parseInt(args[1]));
	 
	    // Ver las suites SSL disponibles

	    System.out.println ("CypherSuites");
	    SSLContext context = SSLContext.getDefault();
	    SSLSocketFactory sf = context.getSocketFactory();
	    
	    String[] cipherSuites = sf.getSupportedCipherSuites();

	    for (int i=0; i<cipherSuites.length; i++) 
	    		;//System.out.println (cipherSuites[i]);
	    
	    
	    
	    System.out.println ("Comienzo SSL Handshake");

	    socket.startHandshake();
	    
	    System.out.println ("Fin SSL Handshake");

	    PrintWriter out = new PrintWriter(
							  new BufferedWriter(
							  new OutputStreamWriter(
									  socket.getOutputStream())));

	    out.println("GET " + "/" + args[2]  + " "  + " HTTP/1.0");
	    out.println();
	    out.flush();

	    System.out.println("GET " + "/" + args[2]  + " " + "HTTP/1.0");
	    /*
	     * Make sure there were no surprises
	     */
	    if (out.checkError())
			System.out.println("SSLSocketClient:  java.io.PrintWriter error");

	    /* Leer respuesta */
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
    /******************************************************
		definirKeyStores()
    *******************************************************/
	private static void definirKeyStores()
	{
		
		// Almacen de claves
		
		System.setProperty("javax.net.ssl.keyStore",         raizMios + "KeyStoreCliente_2017.jce");
		System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", "123456");

		// Almacen de confianza
	  
		System.setProperty("javax.net.ssl.trustStore",          raizMios + "TrustStoreCliente_2017.jce");
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "123456");


		/**/
	}

	private static void definirKeyStoresEjemploJSSE()
	{

		// ----  Almacenes del ejemplo del manual de JSSE. -----------
		
		// Almacen de claves
		
		System.setProperty("javax.net.ssl.keyStore",         raiz + "testkeys.jks");
		System.setProperty("javax.net.ssl.keyStoreType",     "JKS");
	    System.setProperty("javax.net.ssl.keyStorePassword", "passphrase");
	
	    // Almacen de confianza
	    
//	    System.setProperty("javax.net.ssl.trustStore",          raiz + "samplecacerts.jks");
//		System.setProperty("javax.net.ssl.trustStoreType",     "JKS");
//	    System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

	
	}

}