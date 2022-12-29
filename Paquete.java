import java.io.*;
import java.util.Date;
import java.text.SimpleDateFormat;

import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.lang.*;
import javax.crypto.spec.SecretKeySpec;


public class  Paquete implements Serializable {
    private Archivo archivo; //con el documento cifrado por clave K
	private String instruccion;
	private byte[] claveK;
	private java.security.cert.Certificate signCertificate;
	private java.security.cert.Certificate authCertificate;
  	


	public java.security.cert.Certificate getAuthCertificate() {
		return this.authCertificate;
	}

	public void setAuthCertificate(java.security.cert.Certificate authCertificate) {
		this.authCertificate = authCertificate;
	}

	public java.security.cert.Certificate getSignCertificate() {
		return this.signCertificate;
	}

	public void setSignCertificate(java.security.cert.Certificate signCertificate) {
		this.signCertificate = signCertificate;
	}

	public Archivo getArchivo() {
		return this.archivo;
	}

	public void setClaveK(SecretKey clave){
		this.claveK=clave.getEncoded();

		return;
	}
	public SecretKey getClaveK(){
		SecretKey originalKey = new SecretKeySpec(claveK, 0, claveK.length, "AES");
		return originalKey;

	}

	public void setArchivo(Archivo archivo) {
		this.archivo = archivo;
	}

	public String getInstruccion() {
		return this.instruccion;
	}

	public void setInstruccion(String instruccion) {
		this.instruccion = instruccion;
	}



 //Cifrado por la calve pública del cliente o servidor
	public void cifrarClaveK(PublicKey pubKey,String algoritmo) throws Exception {
		Cipher cipher = Cipher.getInstance(algoritmo);
		cipher.init(Cipher.ENCRYPT_MODE,pubKey);
		this.claveK=cipher.doFinal(this.claveK);
		return;
	}
	public void descifrarClaveK(PrivateKey privKey,String algoritmo) throws Exception {
		//Hay que descifrar this.claveK
		Cipher cipher = Cipher.getInstance(algoritmo);//RSA/ECB/PKCS1Padding
        cipher.init(Cipher.DECRYPT_MODE, privKey);
		this.claveK=cipher.doFinal(this.claveK);
		return;

	}

    public Paquete(Archivo archivo, String instruccion, byte[] claveK) {
        this.archivo=archivo;
        this.instruccion=instruccion;
	}
	public Paquete() {

    }

}
