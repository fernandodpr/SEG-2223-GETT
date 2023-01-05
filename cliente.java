//IMPORT
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
    import javax.net.ssl.CertPathTrustManagerParameters;
    import javax.net.ssl.KeyManagerFactory;
    import javax.net.ssl.SSLContext;
    import javax.net.ssl.SSLSession;
    import javax.net.ssl.SSLSocket;
    import javax.net.ssl.SSLSocketFactory;
    import javax.net.ssl.TrustManager;
    import javax.net.ssl.TrustManagerFactory;
    import java.security.cert.CertPathBuilder;
    import java.security.cert.PKIXBuilderParameters;
    import java.security.cert.PKIXRevocationChecker;
    import java.security.cert.X509CertSelector;
    import java.security.cert.X509Certificate;
    import java.nio.file.Paths;
    import java.nio.file.Path;
    import java.nio.file.Files;
    import java.util.Arrays;
    import java.util.Base64;
    import java.util.EnumSet;
    import java.security.MessageDigest;
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
                    putdocumento();
                    break;
                case "B":
                    getdocumento();
                    break;
                case "S":
                    salir = true;
                    break;
                default:
                    break;
            }
        }while(!salir);
    }
    ///GET DOCUMENTO

    public static void getdocumento(){
        String file = "";
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
            file = solicitarTexto("Introduce el número de archivo que deseas recuperar:",def);
            //file=filesPath+"/"+file+".sentfile";
            Debug.info("Se va a solicitar el archivo:  "+file);

        }catch (Exception e){
            e.printStackTrace();
        }

        try {
            //Solicitud de los datos
            String keyStorePath = solicitarArchivo("keyStore","./Crypto/Cliente/KeyStoreCliente");
            String psswd = solicitarPassword("123456");
            String trustStorePath = solicitarArchivo("trustStore","./Crypto/Cliente/TrustStoreCliente");

            //Creación de socket
            SSLSocket socket = handshakeTLS("localhost",8090,keyStorePath,trustStorePath,psswd,"localhost");

            boolean resultado = solicitudServidor(socket,keyStorePath,file,trustStorePath,psswd);
            Debug.info("Peticion enviada");
            resultado=respuestaServidor(socket,keyStorePath,file,trustStorePath,psswd);

        } catch(javax.net.ssl.SSLHandshakeException e){
          if(e.getMessage().equals("chiphersuite")){
            Debug.warn("Error al establecer el Handshake ¿Ha introducido un protocolo correcto?");
          }
        } catch (Exception e){
          e.printStackTrace();
        }
        return;
    }
    private static boolean solicitudServidor(SSLSocket socket,String keyStorePath,String doc, String trustStorePath, String pswd){
        try {
            Paquete paquete = new Paquete();
            KeyStore keyStore;



            ObjectOutputStream  outputSocketObject = new ObjectOutputStream(socket.getOutputStream());
            paquete.setInstruccion("GET:"+doc);

                SSLSession session = socket.getSession();
                java.security.cert.Certificate[] localcerts = session.getLocalCertificates();
                paquete.setAuthCertificate(localcerts[0]);


            outputSocketObject.writeObject(paquete);

        } catch (Exception e) {
            //TODO: handle exception
            e.printStackTrace();
        }
        return true;
    }
    private static boolean respuestaServidor(SSLSocket socket,String keyStorePath,String doc, String trustStorePath, String pswd){
        KeyStore keyStore;
        try {
            BufferedReader socketin = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ObjectInputStream inputSocketObject = new ObjectInputStream(socket.getInputStream());
            Paquete paqueteRecibido = (Paquete)inputSocketObject.readObject();

            keyStore  = KeyStore.getInstance("JCEKS");
            keyStore.load(new FileInputStream(keyStorePath), pswd.toCharArray());
            //Verificar el certificado del servidor
            //Descifrar el Documento

                if(paqueteRecibido.getInstruccion().contains("ERROR")){
                    Debug.warn("Se ha producido un error");


                    if(paqueteRecibido.getInstruccion().contains("401")) throw new Exception("401");

                }
                String alias = "cliente-auth (cliente-sub ca)"; //TODO: Hay que cambiar esto!!
                //alias=solicitarTexto("Introduzca el alias del certificado de firma",alias);
                PrivateKey authPrivateKey = (PrivateKey)keyStore.getKey(alias,"123456".toCharArray());

                if(paqueteRecibido.getArchivo().isCifrado()){
                    paqueteRecibido.descifrarClaveK(authPrivateKey,"RSA"); //Se descrifra la clave K
                    Debug.info("Se ha desencriptado la clave K");
                    IvParameterSpec iv = new IvParameterSpec(new byte[16]);
                    paqueteRecibido.getArchivo().descifrar(paqueteRecibido.getClaveK(),"AES/CBC/PKCS5Padding");
                    paqueteRecibido.getArchivo().guardaDocumentoDatos("Cliente-RespuestaServidor");
                    Debug.info("Se ha desencriptado el documento");
                }else{
                    Debug.warn("El documento ya estaba desencriptado");
                }
            //Verificar SigRd
                if(paqueteRecibido.getArchivo().verificar(paqueteRecibido.getSignCertificate(),"SHA512withRSA",false)){ //TODO: Quitar ese or, era para poder continuar desarrollando
                    Debug.warn("La firma del documento es correcta.");
                }else{
                    Debug.warn("La verificación de la firma ha fallado");
                }
                //TODO: Lo mismo que en la otra verificación hacerlo con Throws
            //Verificar el hash
                //Get hash del documento recibido
                byte[] hashecito = getHash(paqueteRecibido.getArchivo().getDocumento());
                Debug.info(hashecito);
                //Cargar el archivo de HASH guardado en el sistema de archivos
                byte[] data=null;
                try {
                    Path path = Paths.get(doc);
                    data = Files.readAllBytes(path);
                } catch (Exception e) {
                    // TODO: handle exception
                    Debug.info(e.getMessage());

                }


                if(Arrays.equals(hashecito,data)){
                    Debug.info("Los dos hashes coinciden");
                }else{
                    //TODO: Larga excepcion
                    Debug.info("Los dos hashes coinciden"); //Este mensaje tendría que ir en la excepción
                }

            //Pregunar si se quiere guardar el original
        } catch (Exception e) {
            e.printStackTrace();
            //TODO: handle exception
            if(e.getMessage().contains("401")){
                Debug.warn("No tienes permiso para acceder a ese archivo.");
            }
        }
        return false;
    }
    ///PUT DOCUMENTO
    public static void putdocumento(){
        try {
            //Solicitud de los datos
            String keyStorePath = solicitarArchivo("keyStore","./Crypto/Cliente/KeyStoreCliente");
            String psswd = solicitarPassword("123456");
            String trustStorePath = solicitarArchivo("trustStore","./Crypto/Cliente/TrustStoreCliente");

            //Creación de socket
            SSLSocket socket = handshakeTLS("localhost",8090,keyStorePath,trustStorePath,psswd,"localhost");

            //Confección del documento
            //Hay que revisar que el nombre del archivo no sea demasiado grande se puede hacer con la clase Path
            Path documentPath = Paths.get(solicitarArchivo("documento","./lorem"));//TODO: error abrir documento que no existe
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
            //paqueteRecibido.getArchivo().setDocumento(doc.getDocumento());
            if(paqueteRecibido.getArchivo().verificar(paqueteRecibido.getSignCertificate(),"SHA512withRSA",false)){
              Debug.info("Se ha verificado la firma ");
            }else{
                Debug.warn("La verificación de firma ha fallado.");
                //TODO: Esto creo que se podría gestionar con excepción para poder detener la ejecución del método
            }


            //Hash

            storeHash(getHash(paqueteRecibido.getArchivo().getDocumento()),String.valueOf(paqueteRecibido.getArchivo().getNumeroRegistro())); //No me queda muy claro como relacionar el id del documento con el hash creo que sería adecuado hacer
            //deleteFile(documentPath);
            Debug.warn("Se ha almacenado el archivo con idRegistro: "+paqueteRecibido.getArchivo().getNumeroRegistro());



            socket.close();
        } catch (java.nio.file.NoSuchFileException e){
           Debug.warn("Error no existe el archivo.");
        } catch(javax.net.ssl.SSLHandshakeException e){
          if(e.getMessage().equals("chiphersuite")){
            Debug.warn("Error al establecer el Handshake ¿Ha introducido un protocolo correcto?");
          }
        } catch (Exception e){
          e.printStackTrace();
        }
        return;
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
                //DUDA por que le mandamos las claves privadas??
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
                    keyGen.init (128);
                // Generamos una clave
                    SecretKey claveK = keyGen.generateKey();
                    Debug.info(claveK.getEncoded());

                    byte[] rawData =claveK.getEncoded();

                    String encodedKey = Base64.getEncoder().encodeToString(rawData);
                    Debug.info("Se ha generado la clave K: " + encodedKey);


                //Se cifra el Archivo (simetrico)
                    doc.cifrar(claveK,"AES/CBC/PKCS5Padding");
                    Debug.info("Se ha cifrado el archivo.");
                //Establecemos en el paquete la clave K
                    paquete.setClaveK(claveK);
                //Ciframos la clave K con auth del Server
                    SSLSession session = socket.getSession();
                    java.security.cert.Certificate[] servercerts = session.getPeerCertificates();
                    paquete.cifrarClaveK(servercerts[0].getPublicKey(),"RSA");
                    Debug.info("Se ha cifrado la clave K.");

            //Se completa la información del paquete
                paquete.setSignCertificate(signCertificate);
                paquete.setAuthCertificate(authCertificate);
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
    //METODOS DE CONEXION
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


            //OCSP Stapling
            if(solicitarTexto("Activar comprobación OCSPStapling?(SI/NO)", "NO").contains("SI")){
                Debug.info("Se ha activado OCSPStapling");
            }else{
                Debug.info("No se realizará comprobación mediante OCSPStapling");

            }
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


            //OCSP
            String comp=solicitarTexto("Activar comprobación OCSP?(SI/NO)", "NO");
            Debug.info(comp);
            if(comp.contains("SI")){
                String ocspResponderURI=solicitarTexto("Introduce la URI del OCSP Responder", "http://"+IpOCSPResponder+":8092");
                //  1. Crear PKIXRevocationChecker
                    CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
                    PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
                    rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
                    rc.setOcspResponder(new URI(ocspResponderURI));  // Aqui poner la ip y puerto donde se haya lanzado el OCSP Responder
                //  3. Crear los parametros PKIX y el PKIXRevocationChecker
                    PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ksTrustStore, new X509CertSelector());
                    pkixParams.addCertPathChecker(rc);
                    pkixParams.setRevocationEnabled(false); // habilitar la revocacion (por si acaso)
                    tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init(new CertPathTrustManagerParameters(pkixParams));
                    //ocsp.responderCertSubjectName

            }else{
                Debug.info("No se han proporcionado parámetros para OCSP.");
                tmf = TrustManagerFactory.getInstance("SunX509");
                tmf.init(ksTrustStore);
            }

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
                int ciphnum = 0;
                do{
                  System.out.println("############Selecciona un cipher suite: ############");

                  String ciphnumstring = consola.readLine();
                  try{
                    if(!ciphnumstring.equals(""))ciphnum = Integer.parseInt(ciphnumstring);
                    cipherSuitesHabilitadas[0]=cipherSuites[ciphnum];
                    System.out.println("Has seleccionado:   "+ cipherSuitesHabilitadas[0]);
                  }catch(Exception e){
                    Debug.warn("Tiene que ser un numero.");
                    ciphnum = -1;
                  }

                }while(ciphnum ==-1);

            //Creación del socket
                socket = (SSLSocket) factory.createSocket("localhost", 8090);
                socket.setEnabledCipherSuites(cipherSuitesHabilitadas);
                socket.setEnabledProtocols(protocols);
            //Empezamos el Handshake
                System.out.println("\n*************************************************************");
                System.out.println("  Comienzo SSL Handshake -- Cliente y Servidor Autenticados     ");
                System.out.println("*************************************************************");

                try{
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
                }catch(javax.net.ssl.SSLHandshakeException e){
                   // Debug.warn("Error al establecer el Handshake ¿Ha introducido un protocolo correcto?");
                   throw new javax.net.ssl.SSLHandshakeException("chiphersuite");
                }
    }
    private static void definirRevocacionOCSP(){
		// Almacen de claves
		System.setProperty("com.sun.net.ssl.checkRevocation","true");
		System.setProperty("ocsp.enable","true");

	}
    private static void definirRevocacionOCSPStapling(){
		// Almacen de claves
		System.setProperty("jdk.tls.client.enableStatusRequestExtension",   "true");
		System.setProperty("com.sun.net.ssl.checkRevocation",        "true");
		System.setProperty("ocsp.enable",                            "false");

    }
    //Metodos de IO
    private static String solicitarArchivo(String tipo,String def){
        String archivo=null;
        try {
            System.out.println("Introduzca el path de "+tipo+" ["+def+"]:");
            BufferedReader consola = new BufferedReader(new InputStreamReader(System.in));
            archivo = consola.readLine();
        } catch (Exception e) {
          e.printStackTrace();
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
          e.printStackTrace();
        }
        if (data.length()<2){
            return def;
        }else{
            return data ;
        }


    }
    private static String solicitarPassword(String def){
        String passwd1=null;
        String passwd2=null;
        try {
            do{
                System.out.println("Introduzca la clave del keystore  ["+def+"]:");
                BufferedReader consola = new BufferedReader(new InputStreamReader(System.in));
                passwd1 = consola.readLine();
                System.out.println("Confirme la clave del keystore  ["+def+"]:");
                passwd2 = consola.readLine();
            }while(!passwd1.equals(passwd2));
        } catch (Exception e) {
          e.printStackTrace();
        }
        if(passwd1.length()<1){
            return def;
        }else{
            return passwd1;
        }


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
    //Metodos de archivos
    private static void storeHash(byte[] hash,String idDoc){
        try {
            Path path = Paths.get(idDoc+".sentfile");
            Files.write(path, hash);
        } catch (Exception e) {
            //TODO: handle exception
            e.printStackTrace();
        }


    }
    private static void deleteFile(Path documentPath){

        if (documentPath.toFile().delete()) {
        System.out.println("Archivo eliminado: " + documentPath.toFile().getName());
        } else {
        System.out.println("Fallo al eliminar el archivo");
        }
    }
    private static List<String> buscaArchivos(Path path, String fileExtension)
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
    public static byte[] getHash(byte[] array) {
        byte [] doc_hash = null;

        try {

            MessageDigest messageDigest = MessageDigest.getInstance ("SHA-256");
            doc_hash = messageDigest.digest (array);

        } catch (Exception e) {

            e.printStackTrace ();
        }

        return doc_hash;
        //Fuente: https://www.baeldung.com/sha-256-hashing-java
    }
}
