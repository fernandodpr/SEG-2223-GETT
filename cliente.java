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

import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class  cliente{

    //private static String raizAlmacenes = null;
    private static String raizAlmacenes = "./Crypto/";
    private static String keyStorePath   = raizAlmacenes + "Cliente/KeyStoreCliente";
    private static String trustStorePath = raizAlmacenes + "Cliente/TrustStoreCliente";


    public static void main(String[] args) throws Exception {

        String host =null;
        int port = 8085;
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
            try{
                try{
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


                    factory = sslContext.getSocketFactory();


                    System.out.println("******** CypherSuites Disponibles **********");
                    cipherSuites = factory.getSupportedCipherSuites();
                        for (int i = 0; i < cipherSuites.length; i++){
                          if(cipherSuites[i].contains("RSA")){
                            System.out.println(i+"    "+cipherSuites[i]);
                          }
                        }
                        System.out.println("############Selecciona un cipher suite: ############");
                        String ciphnumstring = consola.readLine();
                        int ciphnum = Integer.parseInt(ciphnumstring);
                        cipherSuitesHabilitadas[0]=cipherSuites[ciphnum];
                        System.out.println("Has seleccionado:   "+ cipherSuitesHabilitadas[0]);




                } catch (Exception e){
                    e.printStackTrace();
                }

                SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 8090);
                socket.setEnabledCipherSuites(cipherSuitesHabilitadas);
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


                    // Crea generador de claves
                    KeyPairGenerator keyPairGen;
                    keyPairGen = KeyPairGenerator.getInstance("RSA");

                    // Crea generador de claves

                    keyPairGen.initialize(2048);

                    // Generamos un par de claves (publica y privada)
                    KeyPair     keypair    = keyPairGen.genKeyPair();
                    PrivateKey  privateKey = keypair.getPrivate();
                    PublicKey   publicKey  = keypair.getPublic();


                    //se pueden eliminar parametros y ese Provider (SunJCE) dudo que esté bn
                    arqtest.firmar(privateKey,"SunJCE","SHA512withRSA","RSA",true);

                    Paquete paqtest = new Paquete(arqtest,"Instruccion",publicKey.getEncoded());



                    outputSocketObject.writeObject(paqtest);


                    outputSocketObject.flush();

                    if(socketout.checkError())
                        System.out.println("SSLSocketClient: java.io.PrintWriter error");

                    BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                    String inputLine;

                   // while ((inputLine = socketin.readLine()) != null)
                     //   System.out.println(inputLine);

                       // outputSocketObject.close();
                        // socketout.close();
                        // socket.close();
            } catch (Exception e) {
			    e.printStackTrace();
		    }





    }
}
