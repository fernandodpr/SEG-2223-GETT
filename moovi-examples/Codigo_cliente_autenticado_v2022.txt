package ClienteWeb;

/*************************************************************************
 SSLSocketClientWithClientAuth  Codigo para cliente autenticado
 
	SEG Curso 3 Plan Bolonia, Curso 2021/22
	Fecha: 10/10/2021
	Version: 1.3
*************************************************************************/

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/****************************************************************************
 * This example shows how to set up a key manager to do client authentication if
 * required by server.
 *
 * This program assumes that the client is not inside a firewall. The
 * application can be modified to connect to a server outside the firewall by
 * following SSLSocketClientWithTunneling.java.
 * 
 ****************************************************************************/
public class SSLSocketClientWithClientAuth2022 {


	private static String raizAlmacenes = "C:/Escuela/SEG/Laboratorio/cliente/";

	public static void main(String[] args) throws Exception {

		String host = null;
		int    port = 9001;
		String path = null;
		char[] contraseÃ±aAlmacen = "123456".toCharArray();
		char[] contraseÃ±aEntrada = "123456".toCharArray();
		
		String[] cipherSuites = null;

		definirKeyStores();

		for (int i = 0; i < args.length; i++)
			System.out.println(args[i]);

		if (args.length < 3) {
			System.out.println("USAGE: java SSLSocketClientWithClientAuth " + "host port requestedfilepath");
			System.exit(-1);
		}

		try {
			host = args[0];
			port = Integer.parseInt(args[1]);
			path = args[2];
		} catch (IllegalArgumentException e) {
			System.out.println("USAGE: java SSLSocketClientWithClientAuth " + "host port requestedfilepath");
			System.exit(-1);
		}

		try {

			/*****************************************************************************
			 * Crear un key manager para la autentication del cliente. 
			 * Usar el TrustStore y secureRandom por defecto.
			 ****************************************************************************/
			SSLSocketFactory factory = null;

			SSLContext ctx;
			KeyManagerFactory kmf;
			KeyStore ks;

			try {

				ctx = SSLContext.getInstance("TLS");

				// Definir el/los KeyManager.
				//
				// Ahora son necesarios ya que el cliente necesita autenticarse y por tanto
				// tenemos que informar al SSL de donde tomar las credenciales del cliente.
				//
				kmf = KeyManagerFactory.getInstance("SunX509");
				ks = KeyStore.getInstance("JCEKS");
				ks.load(new FileInputStream(ficheroKeyStore), contraseÃ±aAlmacen);
				kmf.init(ks, contraseÃ±aAlmacen);

				/* Se inicializa el contexto pasandole:
				 * 
				 *    - el/los KeyManagers creado/s. 
				 *    - el TrustManager por defecto (null). 
				 *    - el SecureRamdom por defecto (null).
				 */
				
				ctx.init(kmf.getKeyManagers(), null, null);

				// Asignamos un socket al contexto.

				factory = ctx.getSocketFactory();

				/*********************************************************************
				 * Suites del contexto
				 *********************************************************************/
				System.out.println("******** CypherSuites Disponibles **********");
				cipherSuites = factory.getSupportedCipherSuites();
				for (int i = 0; i < cipherSuites.length; i++)
					System.out.println(cipherSuites[i]);

				// Suites habilitadas por defecto

				System.out.println("******* CypherSuites Habilitadas por defecto **********");

				String[] cipherSuitesDef = factory.getDefaultCipherSuites();
				for (int i = 0; i < cipherSuitesDef.length; i++)
					System.out.println(cipherSuitesDef[i]);

			} catch (Exception e) {
				throw new IOException(e.getMessage());
			}

			SSLSocket socket = (SSLSocket) factory.createSocket(host, port);

			String[] cipherSuitesHabilitadas = { "TLS_RSA_WITH_AES_128_CBC_SHA" };

			System.out.println(cipherSuitesHabilitadas[0]);

			socket.setEnabledCipherSuites(cipherSuitesHabilitadas);

			System.out.println("****** CypherSuites Habilitadas  **********");

			String[] cipherSuitesHabilSocket = socket.getEnabledCipherSuites();
			for (int i = 0; i < cipherSuitesHabilSocket.length; i++)
				System.out.println(cipherSuitesHabilSocket[i]);


			System.out.println("\n*************************************************************");
			System.out.println("  Comienzo SSL Handshake -- Cliente y Servidor Autenticados     ");
			System.out.println("*************************************************************");

			socket.startHandshake();

			System.out.println("\n*************************************************************");
			System.out.println("      Fin OK   SSL Handshake");
			System.out.println("*************************************************************");

			PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
			
			out.println("GET /" + path + " HTTP/1.1");
			out.println();
			out.flush();

			if (out.checkError())
				System.out.println("SSLSocketClient: java.io.PrintWriter error");

			/* Leer respuesta */
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

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
	 * definirKeyStores()
	 *****************************************************/
    private static String ficheroKeyStore   = raizAlmacenes + "KeyStoreCliente.jce";
    private static String ficheroTrustStore = raizAlmacenes + "TrustStoreCliente.jce";

	private static void definirKeyStores() {

		// Almacen de credenciales

		System.setProperty("javax.net.ssl.keyStore", ficheroKeyStore);
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", "123456");

		// Almacen de confianza
		
		System.setProperty("javax.net.ssl.trustStore", ficheroTrustStore);
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "123456");

	}

}