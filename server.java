
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;

import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.lang.*;
import java.security.KeyStore;

import java.net.*;
import javax.net.*;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;


import javax.net.ssl.TrustManager;

public class  server{

    //private static String raizAlmacenes = null;
    private static String raizAlmacenes = "./Crypto/";
    private static String keyStorePath   = raizAlmacenes + "Servidor/KeyStoreServidor";
    private static String trustStorePath = raizAlmacenes + "Servidor/TrustStoreServidor";

    public static void main(String[] args) throws Exception {
            SSLServerSocket sslsocket;
            String host =null;
            int port = 8090;
            String[] cipherSuites = null;
            char[] passwdAlmacen = "123456".toCharArray();
            char[] passwdEntrada = "123456".toCharArray();
    
            //KEYSTORE
                System.setProperty("javax.net.ssl.keyStore", keyStorePath);
                System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
                System.setProperty("javax.net.ssl.keyStorePassword", "123456");
    
            //TRUSTSTORE
                System.setProperty("javax.net.ssl.trustStore", trustStorePath);
                System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
                System.setProperty("javax.net.ssl.trustStorePassword", "123456");
    
    
            String[] cipherSuitesHabilitadas={"A"};
            SSLSocketFactory factory = null;
            SSLContext sslContext;
            KeyManagerFactory kmf;
            KeyStore ksKeyStore;
            TrustManagerFactory tmf;
            KeyStore ksTrustStore;
            SSLServerSocketFactory sslServerSocketFactory = null;
            ServerSocketFactory serverSocketFactory = null;
            SSLServerSocket sslServerSocket = null;
    

            try {
                BufferedReader consola = new BufferedReader(new InputStreamReader(System.in));
                //Inicializo el KeyStore
                kmf = KeyManagerFactory.getInstance("SunX509");
                ksKeyStore  = KeyStore.getInstance("JCEKS");
                ksKeyStore.load(new FileInputStream(keyStorePath), passwdAlmacen);
                kmf.init(ksKeyStore,passwdAlmacen);

                //Inicializo el trust manager
                tmf = TrustManagerFactory.getInstance("SunX509");
                ksTrustStore = KeyStore.getInstance("JCEKS");
                ksTrustStore.load(new FileInputStream(trustStorePath), passwdAlmacen);
                tmf.init(ksTrustStore);

                //Configuración del contexto SSL
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(kmf.getKeyManagers(),tmf.getTrustManagers(),null);
                
                
                
                serverSocketFactory = sslContext.getServerSocketFactory();          
            } catch (Exception e) {
                e.printStackTrace();
            }





		try{

        
        sslServerSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port);
        sslServerSocket.setNeedClientAuth(true);

        while(true){

            System.out.println("******** getSupportedCipherSuites **********");
            String[] supportedCipherSuites = sslServerSocket.getSupportedCipherSuites();
                for (int i = 0; i < supportedCipherSuites.length; i++)
                    System.out.println(i+"    "+supportedCipherSuites[i]);


            System.out.println("********getSupportedProtocols **********");
             String[] supportedProtocols = sslServerSocket.getSupportedProtocols();
                    for (int i = 0; i < supportedProtocols.length; i++)
                        System.out.println(i+"    "+supportedProtocols[i]);
                        
                        
            System.out.println("******** CypherSuites Habilitadas **********");
            String[] enabledCipherSuites = sslServerSocket.getEnabledCipherSuites();
                for (int i = 0; i < enabledCipherSuites.length; i++)
                    System.out.println(i+"    "+enabledCipherSuites[i]);
            
            System.out.println("******** getEnabledProtocols **********");
            String[] enabledProtocols = sslServerSocket.getEnabledProtocols();
            for (int i = 0; i < enabledProtocols.length; i++)
                System.out.println(i+"    "+enabledProtocols[i]);        
            

            

            Socket socket = sslServerSocket.accept();
            BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ObjectInputStream inputSocketObject = new ObjectInputStream(socket.getInputStream());

            
            Paquete test = (Paquete)inputSocketObject.readObject();
            
            
            Debug.info(test.getInstruccion());
            Debug.info(test.getArchivo().getNumeroRegistro());
            Debug.info(test.getArchivo().getTimestamp());
            Debug.info(new String(test.getArchivo().getDocumento(), StandardCharsets.UTF_8));
            Debug.info(test.getArchivo().isCifrado());
            Debug.info(test.getArchivo().getNombreDocumento());
            Debug.info("Voy a verificar la firma.");
            /*PublicKey publicKey =
                    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(test.getClaveK()));
            Debug.info("El resultado de la verificación es:  "+test.getArchivo().verificar(publicKey, "SunJCE", "SHA512withRSA", "RSA",true));

            String inputLine;

        inputLine = socketin.readLine();
          //while (() != null){
            System.out.println(inputLine);
            System.out.println("linea");
          //}

*/
        }




        }catch (IOException e) {
		    System.out.println("Class Server died: " + e.getMessage());
		    e.printStackTrace();
		    return;
		}

       /* try{
            // Crea dos canales de salida, sobre el socket
			//		- uno binario  (rawOut)
			//		- uno de texto (out)

			OutputStream rawOut = socket.getOutputStream();

		    PrintWriter out = new PrintWriter(
										new BufferedWriter(
											new OutputStreamWriter(rawOut)));
            try{
				BufferedReader socketin =
				    new BufferedReader(
					new InputStreamReader(socket.getInputStream()));
				while(!socketin.ready()){

				}
				//System.out.print(socketin.getMessage);


			}catch(Exception e){
				e.printStackTrace();
			}



        }catch (IOException e){

        }*/
    }
}
