
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
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;


import javax.net.ssl.TrustManager;

public class  server{
    //private ServerSocket sslServer = null;
    private static String raizAlmacenes = "./";
    private static String ficheroKeyStore   = raizAlmacenes + "elbueno.jce";
    private static String ficheroTrustStore = raizAlmacenes + "elbueno.jce";

    public static void main(String[] args) throws Exception {
        Socket socket;
        int port = 8090;
        String[] cipherSuites = null;

        char[] passwdAlmacen = "123456".toCharArray();
		    char[] passwdEntrada = "123456".toCharArray();

        SSLContext ctx;
        SSLServerSocketFactory sslServerSocketFactory = null;
        ServerSocketFactory serverSocketFactory = null;
        SSLServerSocket sslServerSocket = null;

        KeyManagerFactory kmf;
		    KeyStore ks;

                //KEYSTORE
        System.setProperty("javax.net.ssl.keyStore", ficheroKeyStore);
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", "123456");
                //TRUSTSTORE
    		System.setProperty("javax.net.ssl.trustStore", ficheroTrustStore);
    		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
    		System.setProperty("javax.net.ssl.trustStorePassword", "123456");


		try{
        ctx = SSLContext.getInstance("TLS");

        kmf = KeyManagerFactory.getInstance("SunX509");
        ks  = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(ficheroKeyStore), passwdAlmacen);
        kmf.init(ks,passwdAlmacen);

        ctx.init(kmf.getKeyManagers(),null,null);




        serverSocketFactory = ctx.getServerSocketFactory();
        sslServerSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port);
        sslServerSocket.setNeedClientAuth(true);

        //while(true){
            socket = sslServerSocket.accept();
            BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ObjectInputStream inputSocketObject = new ObjectInputStream(socket.getInputStream());

            
            Paquete test = (Paquete)inputSocketObject.readObject();
            Debug.taco("Quieres ver mi paquete?");
            Debug.info(new String(test.getClaveK(), StandardCharsets.UTF_8));
            Debug.info(test.getInstruccion());
            Debug.info(test.getArchivo().getNumeroRegistro());
            Debug.info(test.getArchivo().getTimestamp());
            Debug.info(new String(test.getArchivo().getDocumento(), StandardCharsets.UTF_8));
            Debug.info(test.getArchivo().isCifrado());
            Debug.info(test.getArchivo().getNombreDocumento());
            Debug.taco("Puta tu madre");
            Debug.info("Voy a verificar la firma.");
            PublicKey publicKey =
                    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(test.getClaveK()));
            Debug.info("El resultado de la verificación es:  "+test.getArchivo().verificar(publicKey, "SunJCE", "SHA512withRSA", "RSA",true));

            String inputLine;

        inputLine = socketin.readLine();
          //while (() != null){
            System.out.println(inputLine);
            System.out.println("linea");
          //}



        //}




        }catch (IOException e) {
		    System.out.println("Class Server died: " + e.getMessage());
		    e.printStackTrace();
		    return;
		}

        try{
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

        }
    }
}
