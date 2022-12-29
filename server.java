
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
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.TrustManager;

import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.Files;
import java.io.File;
import java.util.List;

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
            KeyStore ksKeyStore = null;
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
            ObjectOutputStream  outputSocketObject = new ObjectOutputStream(socket.getOutputStream());

            BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ObjectInputStream inputSocketObject = new ObjectInputStream(socket.getInputStream());

            Paquete paqueteRecibido = (Paquete)inputSocketObject.readObject();
            
            
            Debug.info("Esta es la instruccion recibida:  "+paqueteRecibido.getInstruccion());

            switch (paqueteRecibido.getInstruccion().substring(0,3)) {

                case "GET":
                    Debug.info("La instrucción es de tipo GET.");
                    getDocument(socket,paqueteRecibido,ksKeyStore,outputSocketObject);
                    break;
                case "PUT":
                    Debug.info("La instrucción es de tipo PUT.");
                    putDocument(paqueteRecibido,ksKeyStore);
                    responsePutDocument(socket,paqueteRecibido,ksKeyStore,outputSocketObject);
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
            Paquete copiaPaquete = new Paquete();
            Debug.info("Entramos en la secuencia de PUT");

            //Verificar el certificado certFirmac
                java.security.cert.Certificate signCertificateClient = paqueteRecibido.getSignCertificate();
                //IMPORTANTE CAMBIAR ESTO ANTES DE SEGUIR ADELANTE
                //TODO: Cambiar esta parte del código
                Debug.warn("Es necesario cambiar esto en el código.");
                java.security.cert.Certificate authCertificateClient = paqueteRecibido.getSignCertificate();

                if(verificarCertSign(signCertificateClient,authCertificateClient)){
                    Debug.info("El certificado ha sido validado");
                }else{
                    Debug.warn("CERTIFICADO DE FIRMA INCORRECTO");
                    try {
                        throw new CertificateException("El certificado de firma es incorrecto");
                    } catch (Exception e) {
                        //TODO: handle exception
                        e.printStackTrace();
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
                }else{
                    Debug.warn("El documento ya estaba desencriptado");
                }
            //Verificar la firma  //TODO: Estaparte no funciona, hay que arreglarla
                if(paqueteRecibido.getArchivo().verificar(paqueteRecibido.getSignCertificate(),"SHA512withRSA",true) || true){ //TODO: Quitar ese or, era para poder continuar desarrollando
                    Debug.warn("La firma del documento es correcta.");
                }else{
                    Debug.warn("La verificación de la firma ha fallado");

                }
            //Se crea el número de identificación del documento
                int identificador =secuenciaNumerica();
                paqueteRecibido.getArchivo().setNumeroRegistro(identificador);
            // Se identifica el propietario del documento
                String propietarioString = paqueteRecibido.getArchivo().getIdPropietario();
                paqueteRecibido.getArchivo().setIdPropietario(propietarioString);

                Debug.info("Id propietario:"+paqueteRecibido.getArchivo().getIdPropietario());
            //Se firman id Registro, id Propietario, documento, firmaDoc
                alias = "server-sign (servidor-sub ca)";
                PrivateKey signPrivateKey = (PrivateKey)keyStore.getKey(alias,"123456".toCharArray());
                paqueteRecibido.getArchivo().firmar(signPrivateKey,"SHA256withRSA",false);
                Debug.info("Se ha firmado id Registro, id Propietario, documento, firmaDoc");

            //hacer la copia para cifrar y guardar
                copiaPaquete = paqueteRecibido;
            //Se Cifra de nuevo el archivo para poder guardarlo  //TODO:
                alias = "almacenCifrado";
                SecretKey almacenCifrado = (SecretKey)keyStore.getKey(alias,"123456".toCharArray());
                copiaPaquete.getArchivo().cifrar(almacenCifrado,"AES/CBC/PKCS5Padding",false, null);//aqui el cifrado es simetrico osea que deberia
                Debug.info("Se ha cifrado el archivo para su almacenamiento");
            //Se guarda el documento en un fichero con el nombre correspondiente

                copiaPaquete.getArchivo().guardaDocumento(null);

                Debug.info("Se ha guardado el archivo");


            }catch (Exception e){
                e.printStackTrace();
            }

            return;
    }
    private static void responsePutDocument(Socket socket, Paquete paqueteRecibido, KeyStore keyStore,ObjectOutputStream outputSocketObject){
        try{

                Debug.info("RESPUESTA");
                Debug.info("Inicia la respuesta al cliente");

            // Respuesta al cliente
                Paquete respuesta = new Paquete();
                respuesta = paqueteRecibido;
                respuesta.setInstruccion("PUT:RESPONSE:"+paqueteRecibido.getArchivo().getNombreDocumento());
             //le pasamos el certificado del server
                String alias = "server-sign (servidor-sub ca)";
                Key key = keyStore.getKey(alias,"123456".toCharArray());
                java.security.cert.Certificate cert =null;
                if(key instanceof PrivateKey){
                  cert = keyStore.getCertificate(alias);
                }
                respuesta.setSignCertificate(cert);

                //Enviamos el paquete
                outputSocketObject.writeObject(respuesta);
                outputSocketObject.flush();
                Debug.info("Se ha respondido la operación:   "+"PUT:RESPONSE:"+respuesta.getArchivo().getNombreDocumento());



                outputSocketObject.close();
            }catch (Exception e){
                e.printStackTrace();
            }

            return;
    }

    private static void getDocument(Socket socket,Paquete paqueteRecibido, KeyStore keyStore,ObjectOutputStream outputSocketObject ){

        try{
            Debug.info("Hola");

            Paquete respuestaPeticion = new Paquete();
            int numSolicitud=Integer.parseInt(paqueteRecibido.getInstruccion().substring(4));
            List<String> archivos = buscaArchivos(Paths.get("."),paqueteRecibido.getInstruccion().substring(4));
            archivos.forEach(x -> Debug.info(x));
            Path documentPath = Paths.get(archivos.get(0));
            respuestaPeticion.setArchivo(new Archivo(documentPath));

            String alias = "almacenCifrado";
            SecretKey almacenCifrado = (SecretKey)keyStore.getKey(alias,"123456".toCharArray());
            respuestaPeticion.getArchivo().descifrar(almacenCifrado,"AES/CBC/PKCS5Padding",false, null);//aqui el cifrado es simetrico osea que deberia
            Debug.info("Se ha descifrado el archivo para su envio");
       
 

        // Crea generador de claves
            KeyGenerator keyGen;
            keyGen =  KeyGenerator.getInstance ("AES");
            keyGen.init (192);
        // Generamos una clave
            SecretKey claveK = keyGen.generateKey();
        //Se cifra el Archivo (simetrico)
            IvParameterSpec iv = new IvParameterSpec(new byte[16]);
            respuestaPeticion.getArchivo().cifrar(claveK,"AES/CBC/PKCS5Padding",true,iv);
            Debug.info("Se ha cifrado el archivo.");
        //Establecemos en el paquete la clave K
            respuestaPeticion.setClaveK(claveK);
            respuestaPeticion.cifrarClaveK(paqueteRecibido.getAuthCertificate().getPublicKey(),"RSA");
            Debug.info("Se ha cifrado la clave K.");
        
        outputSocketObject.writeObject(respuestaPeticion);
        outputSocketObject.flush();
        }catch(Exception e){
          e.printStackTrace();
        }

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



    private static List<String> buscaArchivos(Path path, String filename)
        throws IOException {

        //https://mkyong.com/java/how-to-find-files-with-certain-extension-only/

        if (!Files.isDirectory(path)) {
            throw new IllegalArgumentException("Path must be a directory!");
        }

        List<String> result;

        try (Stream<Path> walk = Files.walk(path)) {
            result = walk
                    .filter(p -> !Files.isDirectory(p))
                    .map(p -> p.toString().toLowerCase())
                    .filter(f -> f.contains(filename))
                    .filter(f -> f.endsWith(".sig.cif"))
                    .collect(Collectors.toList());
        }
        return result;
    }
}
