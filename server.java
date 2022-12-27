
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
import javax.net.ssl.HandshakeCompletedEvent;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
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
import java.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

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
            KeyStore ksKeyStore = null;//duda
            TrustManagerFactory tmf;
            KeyStore ksTrustStore;
            SSLServerSocketFactory sslServerSocketFactory = null;
            ServerSocketFactory serverSocketFactory = null;
            SSLServerSocket sslServerSocket = null;

            //duda
            ksKeyStore  = KeyStore.getInstance("JCEKS");
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


            Socket socket = sslServerSocket.accept();
            BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ObjectInputStream inputSocketObject = new ObjectInputStream(socket.getInputStream());

            Paquete paqueteRecibido = (Paquete)inputSocketObject.readObject();

            Debug.info("Esta es la instruccion recibida:  "+paqueteRecibido.getInstruccion());

            switch (paqueteRecibido.getInstruccion().substring(0,3)) {

                case "GET":
                    Debug.info("La instrucción es de tipo GET.");
                    break;
                case "PUT":
                    Debug.info("La instrucción es de tipo PUT.");
                    putDocument(paqueteRecibido,ksKeyStore);
                    break;
                default:
                    break;
            }

            String inputLine;

            inputLine = socketin.readLine();
        }


    }catch (IOException e) {
        System.out.println("Class Server died: " + e.getMessage());
        e.printStackTrace();
        return;
    }


    }
    private static void definirRevocacionOCSPStapling_Metodo1(){
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

    private static void definirRevocacionOCSPStapling_Metodo2(){
    	//
    	//  Metodo 2: Con URL en el codigo java del server  (aqui)
    	//

    		System.setProperty("jdk.tls.server.enableStatusRequestExtension", "true");
	  	System.setProperty("jdk.tls.stapling.responderOverride","true");
		System.setProperty("jdk.tls.stapling.responderURI", "http://192.168.0.50:9080");
		System.setProperty("jdk.tls.stapling.ignoreExtensions", "true");
    }
    private void printsslServerSocketData(SSLServerSocket sslServerSocket){

        Debug.info("******** getSupportedCipherSuites **********");
        String[] supportedCipherSuites = sslServerSocket.getSupportedCipherSuites();
            for (int i = 0; i < supportedCipherSuites.length; i++)
                Debug.info(i+"    "+supportedCipherSuites[i]);


        Debug.info("********getSupportedProtocols **********");
         String[] supportedProtocols = sslServerSocket.getSupportedProtocols();
                for (int i = 0; i < supportedProtocols.length; i++)
                    Debug.info(i+"    "+supportedProtocols[i]);


        Debug.info("******** CypherSuites Habilitadas **********");
        String[] enabledCipherSuites = sslServerSocket.getEnabledCipherSuites();
            for (int i = 0; i < enabledCipherSuites.length; i++)
                Debug.info(i+"    "+enabledCipherSuites[i]);

        Debug.info("******** getEnabledProtocols **********");
        String[] enabledProtocols = sslServerSocket.getEnabledProtocols();
        for (int i = 0; i < enabledProtocols.length; i++)
            Debug.info(i+"    "+enabledProtocols[i]);

        return;
    }
    private static void putDocument(Paquete paqueteRecibido, KeyStore keyStore){
        try{
            Debug.info("Entramos en la secuencia de PUT");

            //Verificar el certificado certFirmac
                java.security.cert.Certificate signCertificateClient = paqueteRecibido.getSignCertificateClient();
                //IMPORTANTE CAMBIAR ESTO ANTES DE SEGUIR ADELANTE
                //TODO: Cambiar esta parte del código
                Debug.warn("Es necesario cambiar esto en el código.");
                java.security.cert.Certificate authCertificateClient = paqueteRecibido.getSignCertificateClient();

                if(verificarCertSign(signCertificateClient,authCertificateClient)){
                    Debug.info("El certificado ha sido validado");
                }else{
                    Debug.warn("CERTIFICADO DE FIRMA INCORRECTO");
                    try {
                        throw new CertificateException("El certificado de firma es incorrecto");
                    } catch (Exception e) {
                        //TODO: handle exception
                    }
                }
            //Desencriptar el documento
                //Es necesario aceder a los datos del keystore para poder acceder a la privada de auth
                    String alias = "server-sign (servidor-sub ca)"; //TODO: Hay que cambiar esto!!
                    //alias=solicitarTexto("Introduzca el alias del certificado de firma",alias);
                    PrivateKey authPrivateKey = (PrivateKey)keyStore.getKey(alias,"123456".toCharArray());

                if(paqueteRecibido.getArchivo().isCifrado()){
                    paqueteRecibido.descifrarClaveK(authPrivateKey,"RSA"); //Se descrifra la clave K
                    Debug.info("Se ha desencriptado la clave K");
                    IvParameterSpec iv = new IvParameterSpec(new byte[16]);
                    paqueteRecibido.getArchivo().descifrar(paqueteRecibido.getClaveK(),"AES/CBC/PKCS5Padding", false, iv);
                    Debug.info("Se ha desencriptado el documento");
                    //prueba
                    guardaDocumentoLimpio(paqueteRecibido.getArchivo());
                }else{
                    Debug.warn("El documento ya estaba desencriptado");
                }
            //Verificar la firma  //TODO: Estaparte no funciona, hay que arreglarla
                if(paqueteRecibido.getArchivo().verificar(paqueteRecibido.getSignCertificateClient(),"SHA512withRSA",true) || true){ //TODO: Quitar ese or, era para poder continuar desarrollando
                    Debug.warn("La firma del documento es correcta.");
                }else{
                    Debug.warn("La verificación de la firma ha fallado");

                }
            //Se crea el número de identificación del documento
                int identificador =secuenciaNumerica();
                paqueteRecibido.getArchivo().setNumeroRegistro(identificador);
            // Se identifica el propietario del documento
                paqueteRecibido.getArchivo().setIdPropietario("Paco Jones"); //TODO: Cambiar esto
            //Se firman id Registro, id Propietario, documento, firmaDoc
                alias = "server-sign (servidor-sub ca)";
                PrivateKey signPrivateKey = (PrivateKey)keyStore.getKey(alias,"123456".toCharArray());
                paqueteRecibido.getArchivo().firmar(signPrivateKey,"SHA256withRSA",false);
                Debug.info("Se ha firmado id Registro, id Propietario, documento, firmaDoc");
            //Se Cifra de nuevo el archivo para poder guardarlo  //TODO:
                alias = "almacenCifrado";
                SecretKey almacenCifrado = (SecretKey)keyStore.getKey(alias,"123456".toCharArray());
                paqueteRecibido.getArchivo().cifrar(almacenCifrado,"AES/CBC/PKCS5Padding",false, null);//aqui el cifrado es simetrico osea que deberia 
                Debug.info("Se ha cifrado el archivo para su almacenamiento");
            //Se guarda el documento en un fichero con el nombre correspondiente
                guardaDocumento(paqueteRecibido.getArchivo());
                Debug.info("Se ha guardado el archivo");


            // Respuesta al cliente
                Paquete respuesta = new Paquete();

                respuesta.setInstruccion("Hola");
                respuesta.setIdPropietario(paqueteRecibido.getArchivo().getIdPropietario());
                respuesta.setSignCertificateServer(signCert);
                respuesta.setFirma_registrador(paqueteRecibido.getArchivo().getFirma_registrador());



            }catch (Exception e){
                e.printStackTrace();
            }

            return;
    }

    private static boolean verificarCertSign(java.security.cert.Certificate firma, java.security.cert.Certificate auth){
        //Verificar de alguna forma los certificados. Ver que tengan el mismo subjet



        /*X509Certificate certFirma = (X509Certificate)firma;
        String subjectFirma = certFirma.getSubjectDN().getName();
        X509Certificate certAuth = (X509Certificate)auth;
        String subjectAuth = certAuth.getSubjectDN().getName();
        return subjectFirma.contains(subjectAuth);  */
        return true;
    }
    private static int secuenciaNumerica(){
        // Nombre del archivo
        String fileName = "index";
        // Número a escribir en el archivo (empezamos por 1000)
        int number = 1000;
        // Creamos el archivo
        File file = new File(fileName);

        // Si el archivo no existe, lo creamos
        if (file.exists()) {
            // Abrimos el archivo para leerlo
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                // Leemos la primera línea del archivo (que debería ser el número)
                String line = br.readLine();
                // Convertimos la línea a número
                number = Integer.parseInt(line);
                number++;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }else{
            try {
                file.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        // Abrimos el archivo para escribir en él
        try (FileWriter fw = new FileWriter(file)) {
            // Escribimos el número en el archivo
            fw.write(String.valueOf(number));
        } catch (IOException e) {
        e.printStackTrace();
        }


        return number;
    }
    private static void guardaDocumento(Archivo documento){
        try {
            //TODO: Crear el filepath
            String filepath =String.valueOf(documento.getNumeroRegistro())+"_"+documento.getIdPropietario()+".sig.cif";
            FileOutputStream fileOut = new FileOutputStream(filepath);
            ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
            objectOut.writeObject(documento);
            objectOut.close();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static void guardaDocumentoLimpio(Archivo documento){//eliminar este método
        try {
            //TODO: Crear el filepath
            String filepath ="prueba.png";
            FileOutputStream fileOut = new FileOutputStream(filepath);
            fileOut.write(documento.getDocumento());
            fileOut.close();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
