import java.io.IOException;
import java.net.URL;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.nio.charset.Charset;


import java.net.HttpURLConnection;

public class OcspVerifier {

    public static void verifyCertificate(X509Certificate certificate, String ocspUrl) throws CertificateException, IOException, CertPathValidatorException {
        // Obtener el número de serie del certificado
            String serialNumber = certificate.getSerialNumber().toString(16);

        // Construir la URL de la petición al servidor OCSP
            String ocspreq = ocspUrl+"?certificate=" + serialNumber;

        // Establecer la conexión HTTP con el servidor OCSP
            URL url = new URL(ocspreq);
            HttpURLConnection  connection = (HttpURLConnection ) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setDoOutput(true);

        // Enviar la petición y obtener la respuesta
            byte[] responseBytes = connection.getInputStream().readAllBytes();
            
            Debug.info("está la respuesta");
            String s=new String(responseBytes);  
            Debug.info(s.contains("good"));
    }
}