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
import javax.crypto.spec.*;
import java.lang.*;
import java.io.File;
import java.util.List;

import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.lang.ProcessHandle.Info;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.cert.X509Certificate;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.Files;

public class  cliente{
    //private static String raizAlmacenes = null;
    private static String raizAlmacenes = "./Crypto/";
    private static String keyStorePath   = raizAlmacenes + "Cliente/KeyStoreCliente";
    private static String trustStorePath = raizAlmacenes + "Cliente/TrustStoreCliente";

    private static final String[] protocols = new String[]{"TLSv1.3"};


    public static void main(String[] args) throws Exception {
        boolean salir = false;
        do{
            switch (menu()) {
                case "A":
                    menu_registro();
                    break;
                case "B":
                    menu_peticion();
                    break;
                case "S":
                    salir = true;
                    break;
                default:
                    break;
            }
        }while(!salir);

        System.out.println("Estamos fuera del recorrido correcto");
        SSLSocket socket = handshakeTLS("localhost",8090,keyStorePath,trustStorePath,"123456","localhost");
        PrintWriter socketout = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
        ObjectOutputStream  outputSocketObject = new ObjectOutputStream(socket.getOutputStream());

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
        arqtest.firmar(privateKey,"SHA512withRSA",true);

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

    private static SSLSocket handshakeTLS(String host, int port,String keyStorePath, String trustStorePath, String pswd, String IpOCSPResponder) throws Exception{

            SSLSocket socket;
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
                ksKeyStore.load(new FileInputStream(keyStorePath), pswd.toCharArray());
                kmf.init(ksKeyStore,pswd.toCharArray());

            //Inicializo el trust manager
                tmf = TrustManagerFactory.getInstance("SunX509");
                ksTrustStore = KeyStore.getInstance("JCEKS");
                ksTrustStore.load(new FileInputStream(trustStorePath), pswd.toCharArray());
                tmf.init(ksTrustStore);

            //Configuración del contexto SSL
                sslContext = SSLContext.getInstance("TLSv1.3");
                sslContext.init(kmf.getKeyManagers(),tmf.getTrustManagers(),null);
                factory = sslContext.getSocketFactory();

            // Estaplecemos los Cipher Suite
                System.out.println("******** CypherSuites Disponibles **********");
                cipherSuites = factory.getSupportedCipherSuites();
                for (int i = 0; i < cipherSuites.length; i++){
                    if(cipherSuites[i].contains("TLS_AES") || cipherSuites[i].contains("TLS_CHACHA")){
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
    private static boolean registrarDocumento(SSLSocket socket,String keyStorePath,Archivo doc, String trustStorePath, String pswd){
        try{
            //CertAuthC es el certificado de autenticación del cliente (que incorpora su identidad id de Propietario).
            //nombreDoc es un nombre, de una longitud maxima de 100 caracteres, para el documento.
            //documento es el contenido del fichero (cualquier tipo de fichero) con la información a registrar.

            Paquete paquete = new Paquete();
            KeyStore keyStore;
            ObjectOutputStream  outputSocketObject = new ObjectOutputStream(socket.getOutputStream());

            //Obtención de datos necesarios
                keyStore  = KeyStore.getInstance("JCEKS");
                keyStore.load(new FileInputStream(keyStorePath), pswd.toCharArray());
                //Aqui no se si sería interesante pedirl al usuario el alias del certificado
                String alias = "cliente-auth (cliente-sub ca)";
                //alias=solicitarTexto("Introduzca el alias del certificado de autenticación",alias);
                PrivateKey authPrivateKey = (PrivateKey)keyStore.getKey(alias,pswd.toCharArray());
                java.security.cert.Certificate authCertificate = keyStore.getCertificate(alias);

                alias = "cliente-sign (cliente-sub ca)";
                //alias=solicitarTexto("Introduzca el alias del certificado de firma",alias);
                PrivateKey signPrivateKey = (PrivateKey)keyStore.getKey(alias,pswd.toCharArray());
                java.security.cert.Certificate signCertificate = keyStore.getCertificate(alias);

            //1. Se firma el archivo
                //Aplicamos el metodo firma de Archivo
                java.security.cert.Certificate[] localcerts = socket.getSession().getLocalCertificates();
                X509Certificate localcert = (X509Certificate)localcerts[0];
                doc.setIdPropietario((String)localcert.getSubjectDN().getName());
                Debug.info("Propietario: "+doc.getIdPropietario());
                doc.firmar(signPrivateKey,"SHA512withRSA",true);

            //2. Se cifra la información de Archivo
                // Crea generador de claves
                    KeyGenerator keyGen;
                    keyGen =  KeyGenerator.getInstance ("AES");
                    keyGen.init (192);
                // Generamos una clave
                    SecretKey claveK = keyGen.generateKey();
                //Se cifra el Archivo (simetrico)
                    IvParameterSpec iv = new IvParameterSpec(new byte[16]);
                    doc.cifrar(claveK,"AES/CBC/PKCS5Padding",true,iv);
                    Debug.info("Se ha cifrado el archivo.");
                //Establecemos en el paquete la calve K
                    paquete.setClaveK(claveK);
                //Ciframos la clave K con auth del Server
                    SSLSession session = socket.getSession();
                    java.security.cert.Certificate[] servercerts = session.getPeerCertificates();
                    paquete.cifrarClaveK(servercerts[0].getPublicKey(),"RSA");
                    Debug.info("Se ha cifrado la clave K.");

            //Se completa la información del paquete
                paquete.setSignCertificateClient(signCertificate);
                paquete.setAuthCertificateClient(authCertificate);
                paquete.setArchivo(doc);
            //Se envía el tipo de operación a realizar
                paquete.setInstruccion("PUT:"+doc.getNombreDocumento());
                outputSocketObject.writeObject(paquete);
                outputSocketObject.flush();
                Debug.info("Se ha enviado la operación:   "+"PUT:"+doc.getNombreDocumento());


                //cerra ObjectOutputStream
                //outputSocketObject.close();

        }catch(Exception e){
        e.printStackTrace();
        }
        return true;
    }



    public static void Registrar_fichero(){
        System.out.println("Hemos enviado un fichero");
        return;
    }
    public static void menu_registro(){
        try {
            //Solicitud de los datos
            String keyStorePath = solicitarArchivo("keyStore","./Crypto/Cliente/KeyStoreCliente");
            String psswd = solicitarPassword();
            String trustStorePath = solicitarArchivo("trustStore","./Crypto/Cliente/TrustStoreCliente");

            //Creación de socket
            SSLSocket socket = handshakeTLS("localhost",8090,keyStorePath,trustStorePath,psswd,"localhost");

            //Confección del documento
            //Hay que revisar que el nombre del archivo no sea demasiado grande se puede hacer con la clase Path
            Path documentPath = Paths.get(solicitarArchivo("documento","./enviotest.png"));
            Archivo doc = new Archivo(Files.readAllBytes(documentPath),documentPath.getFileName().toString());
            Debug.info("Se ha creado el archivo");


            boolean resultado = registrarDocumento(socket,keyStorePath,doc,trustStorePath,psswd);

            BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ObjectInputStream inputSocketObject = new ObjectInputStream(socket.getInputStream());

            Paquete paqueteRecibido = (Paquete)inputSocketObject.readObject();
            if(paqueteRecibido.getInstruccion().substring(0,13).equals("PUT:RESPONSE:")) Debug.info("Ha llegado la respuesta");
            if(paqueteRecibido.getInstruccion().substring(0,14).equals("PUT:RESPONSE:1")) Debug.info("Ha habido un error");
            //proceso de obtencion de PUT RESPONSE
            //Verificar certificado CertFirmaS
            //Verificar firma registrador(getArchivo.getFirma_registrador) con documento(getArchivo.getDocumento())
            // y firmaDoc(getArchivo.getFirma almacenada ya por el usuario)


            //Voy a hacer el hash
            //Supongo que aqui la instruccion y el numero del error esta gestionado
            //Es un poco el código que habría que meter en donde se gestione una de las peticiones exitosas
            //paqueteRecibido.getArchivo().getHash();//PAra hacer esto tendríamos que mandar de vuelta el archivo en la respuesta no estoy seguro de que eso sea lo mas eficiente

            storeHash(doc.getHash(),String.valueOf(paqueteRecibido.getArchivo().getNumeroRegistro())); //No me queda muy claro como relacionar el id del documento con el hash creo que sería adecuado hacer
            deleteFile(documentPath);

            socket.close();
        } catch (Exception e){
        }
        return;
    }
    public static void menu_peticion(){
        try{
            String filesPath = solicitarTexto("Introduzca el path a la carpeta donde encontrar los archivos enviados:",".");
            List<String> archivos = buscaArchivos(Paths.get(filesPath), "sentfile");
            Debug.info("Se han encontrado los siguientes archivos:");
            String def = "";
            for(String s:archivos){
                String[] partes = s.split(".sentfile");
                Debug.info(partes[0].substring(2));
                def=partes[0].substring(2);
            }
            String file = solicitarTexto("Introduce el número de archivo que deseas recuperar:",def);
            //file=filesPath+"/"+file+".sentfile";
            Debug.info("Se va a solicitar el archivo:  "+file);

        }catch (Exception e){
            e.printStackTrace();
        }
        
        try {
            //Solicitud de los datos
            String keyStorePath = solicitarArchivo("keyStore","./Crypto/Cliente/KeyStoreCliente");
            String psswd = solicitarPassword();
            String trustStorePath = solicitarArchivo("trustStore","./Crypto/Cliente/TrustStoreCliente");

            //Creación de socket
            SSLSocket socket = handshakeTLS("localhost",8090,keyStorePath,trustStorePath,psswd,"localhost");

            //Confección del documento
            //Hay que revisar que el nombre del archivo no sea demasiado grande se puede hacer con la clase Path
            Path documentPath = Paths.get(solicitarArchivo("documento","./enviotest.png"));
            Archivo doc = new Archivo(Files.readAllBytes(documentPath),documentPath.getFileName().toString());
            Debug.info("Se ha creado el archivo");


            boolean resultado = registrarDocumento(socket,keyStorePath,doc,trustStorePath,psswd);

            BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ObjectInputStream inputSocketObject = new ObjectInputStream(socket.getInputStream());

            Paquete paqueteRecibido = (Paquete)inputSocketObject.readObject();
            if(paqueteRecibido.getInstruccion().substring(0,13).equals("PUT:RESPONSE:")) Debug.info("Ha llegado la respuesta");
            if(paqueteRecibido.getInstruccion().substring(0,14).equals("PUT:RESPONSE:1")) Debug.info("Ha habido un error");
            //proceso de obtencion de PUT RESPONSE
            //Verificar certificado CertFirmaS
            //Verificar firma registrador(getArchivo.getFirma_registrador) con documento(getArchivo.getDocumento())
            // y firmaDoc(getArchivo.getFirma almacenada ya por el usuario)


            //Voy a hacer el hash
            //Supongo que aqui la instruccion y el numero del error esta gestionado
            //Es un poco el código que habría que meter en donde se gestione una de las peticiones exitosas
            //paqueteRecibido.getArchivo().getHash();//PAra hacer esto tendríamos que mandar de vuelta el archivo en la respuesta no estoy seguro de que eso sea lo mas eficiente

            storeHash(doc.getHash(),String.valueOf(paqueteRecibido.getArchivo().getNumeroRegistro())); //No me queda muy claro como relacionar el id del documento con el hash creo que sería adecuado hacer
            deleteFile(documentPath);

            socket.close();
        } catch (Exception e){
        }
        return;
    }
    private static String solicitarArchivo(String tipo,String def){
        String archivo=null;
        try {
            System.out.println("Introduzca el path de "+tipo+" ["+def+"]:");
            BufferedReader consola = new BufferedReader(new InputStreamReader(System.in));
            archivo = consola.readLine();
        } catch (Exception e) {

        }
        if (archivo.length()<4){
            return def;
        }else{
            return archivo;
        }


    }
    private static String solicitarTexto(String mensaje,String def){
        String data=null;
        try {
            System.out.println(mensaje+"  ["+def+"]:");
            BufferedReader consola = new BufferedReader(new InputStreamReader(System.in));
            data = consola.readLine();
        } catch (Exception e) {

        }
        if (data.length()<4){
            return def;
        }else{
            return data ;
        }


    }
    private static String solicitarPassword(){
        String passwd1;
        String passwd2;
        try {
            do{
                System.out.println("Introduzca la clave del keystore:");
                BufferedReader consola = new BufferedReader(new InputStreamReader(System.in));
                passwd1 = consola.readLine();
                System.out.println("Confirme la clave del keystore:");
                passwd2 = consola.readLine();
            }while(!passwd1.equals(passwd2));
            return passwd1;
        } catch (Exception e) {

        }
        return null;

    }
    public static String menu(){
        String selection = null;
        BufferedReader info = new BufferedReader(new InputStreamReader(System.in));
        try{
             System.out.println("###########¿Que desea hacer?###########");
            System.out.println("Presiona A para enviar archivo al servidor.(registrar_documento)");
            System.out.println("Presiona B para recibir documento. (recuperar_documento)");
            System.out.println("Presiona S para salir.");

            selection = info.readLine();
            selection = selection.toUpperCase();

        }
        catch(Throwable e){
            e.printStackTrace();
        }
        return selection;
    }
    private static void definirRevocacionOCSP(){
		// Almacen de claves
		System.setProperty("com.sun.net.ssl.checkRevocation",        "true");
		System.setProperty("ocsp.enable",                            "true");

	}
    private static void definirRevocacionOCSPStapling(){
		// Almacen de claves
		System.setProperty("jdk.tls.client.enableStatusRequestExtension",   "true");
		System.setProperty("com.sun.net.ssl.checkRevocation",        "true");
		System.setProperty("ocsp.enable",                            "false");

    }
    
    private static void storeHash(String hash,String idDoc){
        try {
            Debug.info("Tengo el hash"+hash.substring(0,20)+" y el núnero de registro "+idDoc);
            PrintWriter out = new PrintWriter(idDoc+".sentfile");
            out.println(hash);
            out.close();
        } catch (Exception e) {
            //TODO: handle exception
        }


    }
    private static void deleteFile(Path documentPath){
        
    if (documentPath.toFile().delete()) { 
      System.out.println("Archivo eliminado: " + documentPath.toFile().getName());
    } else {
      System.out.println("Fallo al eliminar el archivo");
    } 
    }

    public static List<String> buscaArchivos(Path path, String fileExtension)
        throws IOException {

        //https://mkyong.com/java/how-to-find-files-with-certain-extension-only/

        if (!Files.isDirectory(path)) {
            throw new IllegalArgumentException("Path must be a directory!");
        }

        List<String> result;

        try (Stream<Path> walk = Files.walk(path)) {
            result = walk
                    .filter(p -> !Files.isDirectory(p))
                    // this is a path, not string,
                    // this only test if path end with a certain path
                    //.filter(p -> p.endsWith(fileExtension))
                    // convert path to string first
                    .map(p -> p.toString().toLowerCase())
                    .filter(f -> f.endsWith(fileExtension))
                    .collect(Collectors.toList());
        }

        return result;
    }
}
