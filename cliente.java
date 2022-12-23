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
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.cert.X509Certificate;

public class  cliente{

    //private static String raizAlmacenes = null;
    private static String raizAlmacenes = "./Crypto/";
    private static String keyStorePath   = raizAlmacenes + "Cliente/KeyStoreCliente";
    private static String trustStorePath = raizAlmacenes + "Cliente/TrustStoreCliente";

    private static final String[] protocols = new String[]{"TLSv1.3"};


    public static void main(String[] args) throws Exception {
        
                SSLSocket socket = handshakeTLS("localhost",8090,keyStorePath,trustStorePath,"123456","localhost");

                
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

                    while ((inputLine = socketin.readLine()) != null)
                        System.out.println(inputLine);
                        outputSocketObject.close();
                        socketout.close();
                        socket.close();
         


    }

    private SSLSocket handshakeTLS(String host, int port;String keyStorePath, String trustStorePath, String pswd, String IpOCSPResponder) throws Exception{
           
        SSLSocket socket 
            //KEYSTORE
                System.setProperty("javax.net.ssl.keyStore", keyStorePath);
                System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
                System.setProperty("javax.net.ssl.keyStorePassword", pswd);
            //TRUSTSTORE
                System.setProperty("javax.net.ssl.trustStore", trustStorePath);
                System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
                System.setProperty("javax.net.ssl.trustStorePassword", pswd);
            //Variables
                String[] cipherSuitesHabilitadas={"A"};
                SSLSocketFactory factory = null;
                SSLContext sslContext;
                KeyManagerFactory kmf;
                KeyStore ksKeyStore;
                TrustManagerFactory tmf;
                KeyStore ksTrustStore;
                String[] cipherSuites = null;
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
                sslContext = SSLContext.getInstance("TLSv1.3");
                sslContext.init(kmf.getKeyManagers(),tmf.getTrustManagers(),null);
                factory = sslContext.getSocketFactory();

            // Estaplecemos los Cipher Suite
                System.out.println("******** CypherSuites Disponibles **********");
                    cipherSuites = factory.getSupportedCipherSuites();
                        for (int i = 0; i < cipherSuites.length; i++){
                        
                        if(cipherSuites[i].contains("AES") && !cipherSuites[i].contains("WITH_AES")){
                            System.out.println(i+"    "+cipherSuites[i]);
                        }
                        }
                        System.out.println("############Selecciona un cipher suite: ############");
                        String ciphnumstring = consola.readLine();
                        int ciphnum = Integer.parseInt(ciphnumstring);
                        cipherSuitesHabilitadas[0]=cipherSuites[ciphnum];
                        System.out.println("Has seleccionado:   "+ cipherSuitesHabilitadas[0]);

            //Creación del socket
                socket = (SSLSocket) factory.createSocket("localhost", 8090);
                socket.setEnabledCipherSuites(cipherSuitesHabilitadas);
                socket.setEnabledProtocols(protocols);
            //Empezamos el Handshake
                System.out.println("\n*************************************************************");
                System.out.println("  Comienzo SSL Handshake -- Cliente y Servidor Autenticados     ");
                System.out.println("*************************************************************");
                socket.startHandshake();
            //Información de la sesión TLS
                SSLSession session = socket.getSession();
                java.security.cert.Certificate[] servercerts = session.getPeerCertificates();
                java.security.cert.Certificate[] localcerts = session.getLocalCertificates();

                for(int i=0;i<servercerts.length;i++){
                    X509Certificate localcert = (X509Certificate)localcerts[i];
                    System.out.println("Local Certificate: "+(i+1)+"   "+localcert.getSubjectDN().getName());
                }
                
                for(int i=0;i<servercerts.length;i++){
                    X509Certificate peercert = (X509Certificate)servercerts[i];      
                    System.out.println("Peer Certificate: "+(i+1)+"   "+peercert.getSubjectDN().getName());
                }
        return socket;
    }
}
