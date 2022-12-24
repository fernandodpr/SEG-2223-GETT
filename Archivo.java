import java.io.*;
import java.util.Date;
import java.text.SimpleDateFormat;

import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.lang.*;

public class  Archivo implements Serializable  {
    private String numeroRegistro;
    private String timestamp;
    private byte[] documento;  //esto se guarda cifardo
    private boolean cifrado;
    private String nombreDocumento;
    private byte[] firma;
    private byte[] firma_registrador;

	//GETTERS Y SETTERS

	public boolean isCifrado() {
		return this.cifrado;
	}
	public void setCifrado(boolean cifrado) {
		this.cifrado = cifrado;
    }
	public String getNumeroRegistro() {
		return this.numeroRegistro;
	}
	public void setNumeroRegistro(String numeroRegistro) {
		this.numeroRegistro = numeroRegistro;
	}
	public String getTimestamp() {
		return this.timestamp;
	}
	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}
	public byte[] getDocumento() {
		return this.documento;
	}
	public void setDocumento(byte[] documento) {
		this.documento = documento;
	}
	public String getNombreDocumento() {
		return this.nombreDocumento;
	}
	public void setNombreDocumento(String nombreDocumento) {
		this.nombreDocumento = nombreDocumento;
	}
	public byte[] getFirma() {
		return this.firma;
	}
	public void setFirma(byte[] firma) {
		this.firma = firma;
	}
	public byte[] getFirma_registrador() {
		return this.firma_registrador;
	}
	public void setFirma_registrador(byte[] firma_registrador) {
		this.firma_registrador = firma_registrador;
	}

	//Métodos para cifrar

	//Métodos para comprobar firma
    public Archivo(byte[] documento,String nombreDocumento) {
		this.numeroRegistro= null;
		this.timestamp=new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
		this.documento=documento;
		this.cifrado=false;
		this.nombreDocumento=nombreDocumento;
		this.firma=null;
		this.firma_registrador=null;
	}

	public void firmar(PrivateKey privateKey,String algoritmo,boolean cliente) throws Exception {
		Signature signer = Signature.getInstance(algoritmo);
		signer.initSign(privateKey);
		byte[] firma = null;
    	//byte   bloque[]         = new byte[1024];
    	signer.update(this.documento);
		Debug.info("Se ha firmado el archivo: "+ this.nombreDocumento + "");
		if(cliente){
			this.firma=signer.sign();
			Debug.info("Se ha firmado el archivo: "+ this.nombreDocumento + " con un tamaño " +this.firma.length + " por el cliente.");
		}else{
			this.firma_registrador=signer.sign();
			Debug.info("Se ha firmado el archivo: "+ this.nombreDocumento + " con un tamaño " +this.firma_registrador.length + " por el servidor.");
		}

	}
	public void cifrar(PrivateKey privateKey,String provider,String algoritmo,String algoritmo_base,boolean cliente) throws Exception {
		//Hay que cifrar this.documento
		return;
	}
	public void descifrar(PublicKey publicKey,String provider,String algoritmo,String algoritmo_base,boolean cliente) throws Exception {
		//Hay que descifrar this.documento
		return;
	}

	public boolean verificar(PublicKey publicKey,String provider,String algoritmo,String algoritmo_base,boolean cliente) throws Exception {
		Signature verifier=Signature.getInstance(algoritmo);
		byte[] publicBytes  = publicKey.getEncoded();
		EncodedKeySpec keySpec;
		if (publicKey.getFormat().equals("X.509"))
			keySpec = new X509EncodedKeySpec (publicBytes);
		else
			keySpec = new PKCS8EncodedKeySpec(publicBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(algoritmo_base);
		PublicKey  publicKey2 = keyFactory.generatePublic(keySpec);
		// Inicializamos el objeto
		verifier.initVerify(publicKey2);
		verifier.update(this.documento);

		boolean resultado = false;

		if(cliente){
			resultado = verifier.verify(this.firma);
			Debug.info("Se ha comprobado: "+ this.nombreDocumento + "con resultado: "+ resultado);

		}else{
			resultado = verifier.verify(this.firma_registrador);
			Debug.info("Se ha comprobado: "+ this.nombreDocumento + "con resultado: "+ resultado);

		}

		return resultado;
	}


}
