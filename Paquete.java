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
	private java.security.cert.Certificate signCertificateClient;
	private java.security.cert.Certificate authCertificateClient;
	private java.security.cert.Certificate signCertificateServer;
	private java.security.cert.Certificate authCertificateServer;
	private byte[] firma_registrador;

	public byte[] getFirma_registrador() {
		return this.firma_registrador;
	}

	public void setFirma_registrador(byte[] firma_registrador) {
		this.firma_registrador = firma_registrador;
	}


	public java.security.cert.Certificate getSignCertificateServer() {
		return this.signCertificateServer;
	}

	public void setSignCertificateServer(java.security.cert.Certificate signCertificateServer) {
		this.signCertificateServer = signCertificateServer;
	}

	public java.security.cert.Certificate getAuthCertificateServer() {
		return this.authCertificateServer;
	}

	public void setAuthCertificateServer(java.security.cert.Certificate authCertificateServer) {
		this.authCertificateServer = authCertificateServer;
	}

	private String idPropietario;
	private int numeroRegistro;

	public String getIdPropietario() {
		return this.idPropietario;
	}

	public void setIdPropietario(String idPropietario) {
		this.idPropietario = idPropietario;
	}

	public int getNumeroRegistro() {
		return this.numeroRegistro;
	}

	public void setNumeroRegistro(int numeroRegistro) {
		this.numeroRegistro = numeroRegistro;
	}



	public java.security.cert.Certificate getAuthCertificateClient() {
		return this.authCertificateClient;
	}

	public void setAuthCertificateClient(java.security.cert.Certificate authCertificateClient) {
		this.authCertificateClient = authCertificateClient;
	}



	public java.security.cert.Certificate getSignCertificateClient() {
		return this.signCertificateClient;
	}

	public void setSignCertificateClient(java.security.cert.Certificate signCertificateClient) {
		this.signCertificateClient = signCertificateClient;
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
