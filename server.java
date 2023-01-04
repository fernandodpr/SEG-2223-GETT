
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
import java.util.Base64;


public class  server{

    //TODO: Excepcion de tipo FileNotFoundException cuando un keystore no existe



    //private static String raizAlmacenes = null;
    private static String raizAlmacenes = "./Crypto/";
    private static String keyStorePath   = raizAlmacenes + "Servidor/KeyStoreServidor";
    private static String trustStorePath = raizAlmacenes + "Servidor/TrustStoreServidor";
    private static String keyStorePathAuth = raizAlmacenes + "Servidor/KeyStoreServidorAuth";

    public static void main(String[] args) throws Exception {
            SSLServerSocket sslsocket;
            String host =null;
            int port = 8090;
            String[] cipherSuites = null;
            char[] passwdAlmacen = "123456".toCharArray();
            char[] passwdEntrada = "123456".toCharArray();

            //KEYSTORE
                System.setProperty("javax.net.ssl.keyStore", keyStorePathAuth);
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
            KeyManagerFactory kmfAuth;
            KeyStore ksKeyStoreAuth = null;
            TrustManagerFactory tmf;
            KeyStore ksTrustStore;
            SSLServerSocketFactory sslServerSocketFactory = null;
            ServerSocketFactory serverSocketFactory = null;
            SSLServerSocket sslServerSocket = null;

            //duda
            ksKeyStore  = KeyStore.getInstance("JCEKS");
            try {
                Debug.info("Iniciando el servidor...");
                BufferedReader consola = new BufferedReader(new InputStreamReader(System.in));
                //Inicializo el KeyStore
                kmf = KeyManagerFactory.getInstance("SunX509");
                ksKeyStore  = KeyStore.getInstance("JCEKS");
                ksKeyStore.load(new FileInputStream(keyStorePath), passwdAlmacen);
                kmf.init(ksKeyStore,passwdAlmacen);

                //Inicializo el KeyStoreAuth
                kmfAuth = KeyManagerFactory.getInstance("SunX509");
                ksKeyStoreAuth  = KeyStore.getInstance("JCEKS");
                ksKeyStoreAuth.load(new FileInputStream(keyStorePathAuth), passwdAlmacen);
                kmfAuth.init(ksKeyStoreAuth,passwdAlmacen);

                //Inicializo el trust manager
                tmf = TrustManagerFactory.getInstance("SunX509");
                ksTrustStore = KeyStore.getInstance("JCEKS");
                ksTrustStore.load(new FileInputStream(trustStorePath), passwdAlmacen);
                tmf.init(ksTrustStore);

                //Configuración del contexto SSL
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(kmfAuth.getKeyManagers(),tmf.getTrustManagers(),null);

                serverSocketFactory = sslContext.getServerSocketFactory();
            } catch (Exception e) {
                e.printStackTrace();
            }


        try{

            sslServerSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port);
            sslServerSocket.setNeedClientAuth(true);
            int contadorHilos = 0;

            while(true){ //aceptando los multiples clientes
                Socket socket = sslServerSocket.accept();
                Hilo nuevoHilo = Hilo.crear(socket, Integer.toString(contadorHilos), ksKeyStore);
                contadorHilos++;
            }
        }catch (IOException e) {
            System.out.println("Class Server died: " + e.getMessage());
            e.printStackTrace();
            return;
        }
    }

}



class Hilo implements Runnable{
   Thread hilo;
   Socket socket;
   KeyStore ksKeyStore;

   //constructor
   Hilo(Socket socket, String name, KeyStore ksKeyStore){
     hilo = new Thread(this, name);
     this.socket = socket;
     this.ksKeyStore = ksKeyStore;
   }

   //metodo para crear el hulo
   public static Hilo crear (Socket socket, String name, KeyStore ksKeyStore){
     Hilo thisHilo = new Hilo(socket,name,ksKeyStore);
     thisHilo.hilo.start();//inicio de hilo;
     return thisHilo;
   }






      //los metodos del server


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
   private static void putDocument(Paquete paqueteRecibido, KeyStore keyStore,String hilo){
       try{

           Debug.info("[Cliente#"+hilo+"]"+"Entramos en la secuencia de PUT");

           //Verificar el certificado certFirmac
               java.security.cert.Certificate signCertificateClient = paqueteRecibido.getSignCertificate();
               //IMPORTANTE CAMBIAR ESTO ANTES DE SEGUIR ADELANTE
               //TODO: Cambiar esta parte del código
               Debug.warn("Es necesario cambiar esto en el código.");
               java.security.cert.Certificate authCertificateClient = paqueteRecibido.getSignCertificate();

               if(verificarCertSign(signCertificateClient,authCertificateClient,hilo)){

                   Debug.info("[Cliente#"+hilo+"]"+"El certificado ha sido validado");
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
                   String alias = "server-auth (servidor-sub ca)"; //TODO: Hay que cambiar esto!! //server-auth (servidor-sub ca)
                   PrivateKey authPrivateKey = (PrivateKey)keyStore.getKey(alias,"123456".toCharArray());

               if(paqueteRecibido.getArchivo().isCifrado()){
                   paqueteRecibido.descifrarClaveK(authPrivateKey,"RSA"); //Se descrifra la clave K
                   byte[] rawData = paqueteRecibido.getClaveK().getEncoded();

                   String encodedKey = Base64.getEncoder().encodeToString(rawData);
                   Debug.info("[Cliente#"+hilo+"]"+"Se ha desencriptado la clave K: " + encodedKey);

                   paqueteRecibido.getArchivo().descifrar(paqueteRecibido.getClaveK(),"AES/CBC/PKCS5Padding");
                   paqueteRecibido.getArchivo().guardaDocumentoDatos("Servidor-PutDocument");
                   Debug.info("[Cliente#"+hilo+"]"+"Se ha desencriptado el documento");
               }else{
                   Debug.warn("El documento ya estaba desencriptado");
               }
           //Verificar la firma  //TODO: Estaparte no funciona, hay que arreglarla
               if(paqueteRecibido.getArchivo().verificar(paqueteRecibido.getSignCertificate(),"SHA512withRSA",true)){ //TODO: Quitar ese or, era para poder continuar desarrollando
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

               Debug.info("[Cliente#"+hilo+"]"+"Id propietario:"+paqueteRecibido.getArchivo().getIdPropietario());
           //Se firman id Registro, id Propietario, documento, firmaDoc
               alias = "server-sign (servidor-sub ca)";
               PrivateKey signPrivateKey = (PrivateKey)keyStore.getKey(alias,"123456".toCharArray());
               paqueteRecibido.getArchivo().firmar(signPrivateKey,"SHA512withRSA",false);
               Debug.info("[Cliente#"+hilo+"]"+"Se ha firmado id Registro, id Propietario, documento, firmaDoc");



           //hacer la copia para cifrar y guardar

           //Se Cifra de nuevo el archivo para poder guardarlo  //TODO:
               alias = "almacenCifrado";
               SecretKey almacenCifrado = (SecretKey)keyStore.getKey(alias,"123456".toCharArray());
               paqueteRecibido.getArchivo().guardaDocumentoDatos("ParaGuardarAntes");
               paqueteRecibido.getArchivo().cifrar(almacenCifrado,"AES/CFB/PKCS5Padding");//aqui el cifrado es simetrico osea que deberia
               Debug.info("[Cliente#"+hilo+"]"+"Se ha cifrado el archivo para su almacenamiento");
           //Se guarda el documento en un fichero con el nombre correspondiente
               paqueteRecibido.getArchivo().guardaDocumento(null);
               Debug.info("[Cliente#"+hilo+"]"+"Se ha guardado el archivo");


           //Prueba
               paqueteRecibido.getArchivo().descifrar(almacenCifrado,"AES/CFB/PKCS5Padding");
               paqueteRecibido.getArchivo().guardaDocumentoDatos("DescifradoPrueba");







           }catch (Exception e){
               e.printStackTrace();
           }

           return;
   }
   private static void responsePutDocument(Socket socket, Paquete paqueteRecibido, KeyStore keyStore,ObjectOutputStream outputSocketObject,String hilo){
       try{

               Debug.info("[Cliente#"+hilo+"]"+"RESPUESTA");
               Debug.info("[Cliente#"+hilo+"]"+"Inicia la respuesta al cliente");

           // Respuesta al cliente
               Paquete respuesta = new Paquete();
               respuesta.setInstruccion("PUT:RESPONSE:"+paqueteRecibido.getArchivo().getNombreDocumento());

               respuesta.setArchivo(paqueteRecibido.getArchivo());
               respuesta.getArchivo().setDocumento(paqueteRecibido.getArchivo().getDocumento());
           //le pasamos el certificado del server
               String alias = "server-sign (servidor-sub ca)";
               java.security.cert.Certificate signCertificate = keyStore.getCertificate(alias);
               respuesta.setSignCertificate(signCertificate);

           //Enviamos el paquete
               outputSocketObject.writeObject(respuesta);
               outputSocketObject.flush();
               Debug.info("[Cliente#"+hilo+"]"+"Se ha respondido la operación:   "+"PUT:RESPONSE:"+respuesta.getArchivo().getNombreDocumento());



               outputSocketObject.close();
           }catch (Exception e){
               e.printStackTrace();
           }

           return;
   }
   private static void getDocument(Socket socket,Paquete paqueteRecibido, KeyStore keyStore,ObjectOutputStream outputSocketObject ,String hilo){

       try{


           Paquete respuestaPeticion = new Paquete();
           int numSolicitud=Integer.parseInt(paqueteRecibido.getInstruccion().substring(4));
           List<String> archivos = buscaArchivos(Paths.get("."),paqueteRecibido.getInstruccion().substring(4));
           archivos.forEach(x -> Debug.info("[Cliente#"+hilo+"]"+x));
           Path documentPath = Paths.get(archivos.get(0));
           respuestaPeticion.setArchivo(new Archivo(documentPath));



           String alias = "almacenCifrado";

           IvParameterSpec ivi = new IvParameterSpec(new byte[16]);

           SecretKey almacenCifrado = (SecretKey)keyStore.getKey(alias,"123456".toCharArray());

           respuestaPeticion.getArchivo().descifrar(almacenCifrado,"AES/CFB/PKCS5Padding");//aqui el cifrado es simetrico osea que deberia
           respuestaPeticion.getArchivo().guardaDocumentoDatos("ServidorCargaArchivo");
           Debug.info("[Cliente#"+hilo+"]"+"Se ha descifrado el archivo para su envio");

           alias = "server-sign (servidor-sub ca)";
           //alias=solicitarTexto("Introduzca el alias del certificado de firma",alias);
           java.security.cert.Certificate signCertificate = keyStore.getCertificate(alias);
           respuestaPeticion.setSignCertificate(signCertificate);

       // Crea generador de claves
           KeyGenerator keyGen;
           keyGen =  KeyGenerator.getInstance ("AES");
           keyGen.init (192);
       // Generamos una clave
           SecretKey claveK = keyGen.generateKey();
       //Se cifra el Archivo (simetrico)
           IvParameterSpec iv = new IvParameterSpec(new byte[16]);
           respuestaPeticion.getArchivo().cifrar(claveK,"AES/CBC/PKCS5Padding");
           Debug.info("[Cliente#"+hilo+"]"+"Se ha cifrado el archivo.");
       //Establecemos en el paquete la clave K
           respuestaPeticion.setClaveK(claveK);
           respuestaPeticion.cifrarClaveK(paqueteRecibido.getAuthCertificate().getPublicKey(),"RSA");
           Debug.info("[Cliente#"+hilo+"]"+"Se ha cifrado la clave K.");
       outputSocketObject.writeObject(respuestaPeticion);
       outputSocketObject.flush();
       }catch(Exception e){
         e.printStackTrace();
       }

   }
   private static boolean verificarCertSign(java.security.cert.Certificate firma, java.security.cert.Certificate auth,String hilo){
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

   //Runnable
   public void run(){
     Debug.info("[Cliente#"+hilo.getName()+"]"+ "Iniciado.");

     try{
       ObjectOutputStream  outputSocketObject = new ObjectOutputStream(socket.getOutputStream());

       BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));
       ObjectInputStream inputSocketObject = new ObjectInputStream(socket.getInputStream());

       Paquete paqueteRecibido = (Paquete)inputSocketObject.readObject();


       Debug.info("[Cliente#"+hilo.getName()+"]"+"Esta es la instruccion recibida:  "+paqueteRecibido.getInstruccion());

       switch (paqueteRecibido.getInstruccion().substring(0,3)) {

           case "GET":
               Debug.info("[Cliente#"+hilo.getName()+"]"+"La instrucción es de tipo GET.");
               getDocument(socket,paqueteRecibido,ksKeyStore,outputSocketObject,hilo.getName() );
               break;
           case "PUT":
               Debug.info("[Cliente#"+hilo.getName()+"]"+"La instrucción es de tipo PUT.");
               putDocument(paqueteRecibido,ksKeyStore,hilo.getName());
               responsePutDocument(socket,paqueteRecibido,ksKeyStore,outputSocketObject,hilo.getName());
               break;
           default:
               break;
       }

       String inputLine;

       inputLine = socketin.readLine();
     }catch(Exception e){
       Debug.info("[Cliente#"+hilo.getName()+"]"+"Interrumpido.");
       e.printStackTrace();
     }
     Debug.info("[Cliente#"+hilo.getName()+"] terminado.");
   }


}
