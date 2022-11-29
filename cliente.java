
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.security.KeyStore;

import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.lang.*;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class  cliente{

    //private static String raizAlmacenes = null;
    private static String raizAlmacenes = "./";
    private static String ficheroKeyStore   = raizAlmacenes + "elbueno.jce";
    private static String ficheroTrustStore = raizAlmacenes + "elbueno.jce";


    public static void main(String[] args) throws Exception {

        String host =null;
        int port = 8085;
        String[] cipherSuites = null;

        char[] passwdAlmacen = "123456".toCharArray();
		    char[] passwdEntrada = "123456".toCharArray();

        //KEYSTORE
        System.setProperty("javax.net.ssl.keyStore", ficheroKeyStore);
		    System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		    System.setProperty("javax.net.ssl.keyStorePassword", "123456");

        //TRUSTSTORE
		    System.setProperty("javax.net.ssl.trustStore", ficheroTrustStore);
		    System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		    System.setProperty("javax.net.ssl.trustStorePassword", "123456");



        SSLSocketFactory factory = null;
        SSLContext ctx;
		    KeyManagerFactory kmf;
		    KeyStore ks;
            try{
                try{
                    ctx = SSLContext.getInstance("TLS");

                    kmf = KeyManagerFactory.getInstance("SunX509");
                    ks  = KeyStore.getInstance("JCEKS");
                    ks.load(new FileInputStream(ficheroKeyStore), passwdAlmacen);
                    kmf.init(ks,passwdAlmacen);

                    ctx.init(kmf.getKeyManagers(),null,null);
                    factory = ctx.getSocketFactory();

                    System.out.println("******** CypherSuites Disponibles **********");
                    cipherSuites = factory.getSupportedCipherSuites();
                        for (int i = 0; i < cipherSuites.length; i++)
                            System.out.println(cipherSuites[i]);

                    System.out.println("******* CypherSuites Habilitadas por defecto **********");
                        String[] cipherSuitesDef = factory.getDefaultCipherSuites();
                        for (int i = 0; i < cipherSuitesDef.length; i++)
                            System.out.println(cipherSuitesDef[i]);
                } catch (Exception e){
                    throw new IOException(e.getMessage());
                }

                SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 8090);
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
                     PrintWriter socketout = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
                    // OutputStream outputSocket= socket.getOutputStream();
                    ObjectOutputStream  outputSocketObject = new ObjectOutputStream(socket.getOutputStream());
                    //socketout.println(23);

                    String inputString = "Soy el documento";
                    String claveK = "Soy la calve K";
                    Archivo arqtest = new Archivo(inputString.getBytes(),"Soy el nombre del documento");
                    
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
                    
                    
                    
                    arqtest.firmar(privateKey,provider,algoritmo,algoritmo_base,true);
                    
                    Paquete paqtest = new Paquete(arqtest,"Instruccion",publicKey.getEncoded());
                    
                    
                    
                    outputSocketObject.writeObject(paqtest);
                    
                    
                    outputSocketObject.flush();
                    
                    if(socketout.checkError())
                        System.out.println("SSLSocketClient: java.io.PrintWriter error");

                    BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                    String inputLine;

                    while ((inputLine = socketin.readLine()) != null)
                        System.out.println(inputLine);

                        outputSocketObject.close();
                        // socketout.close();
                        // socket.close();
            } catch (Exception e) {
			    e.printStackTrace();
		    }





    }
}
