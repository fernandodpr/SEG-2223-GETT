
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

public class  sslsocketClient{

    private static String raizAlmacenes = null;
    public static void main(String[] args) throws Exception {


        private static String raizAlmacenes = "/home/fer/SEG-2022-GETT/dev-socket/";
        private static String ficheroKeyStore   = raizAlmacenes + "keystore.jce";
        private static String ficheroTrustStore = raizAlmacenes + "keystore.jce";

        String host =null;
        int port = null;
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
                    kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                    ks  = KeyStore.getInstance(KeyStore.getDefaultType());
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
                    PrintWriter socketout = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
                    socketout.println(23);
                    socketout.flush();

                    if (out.checkError())
                        System.out.println("SSLSocketClient: java.io.PrintWriter error");
                    
                    BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                    String inputLine;

                    while ((inputLine = in.readLine()) != null)
                        System.out.println(inputLine);

                    socketin.close();
                    socketout.close();
            
                   socket.close();
            } catch (Exception e) {
			    e.printStackTrace();
		    }





    }
}