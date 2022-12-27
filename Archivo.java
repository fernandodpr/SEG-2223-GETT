import java.io.*;
import java.util.Date;
import java.text.SimpleDateFormat;

import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.lang.*;

public class  Archivo implements Serializable  {
	private int numeroRegistro;
	private String idPropietario;

	public Object getIdPropietario() {
		return this.idPropietario;
	}

	public void setIdPropietario(String idPropietario) {
		this.idPropietario = idPropietario;
	}
;
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
	public int getNumeroRegistro() {
		return this.numeroRegistro;
	}
	public void setNumeroRegistro(int numeroRegistro) {
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
		this.numeroRegistro= 0;
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

		Debug.info("Se ha firmado el archivo: "+ this.nombreDocumento + "");
		if(cliente){
			signer.update(this.documento);
			this.firma=signer.sign();
			Debug.info("Se ha firmado el archivo: "+ this.nombreDocumento + " con un tamaño " +this.firma.length + " por el cliente.");
		}else{
			ByteArrayOutputStream firmaServidor = new ByteArrayOutputStream( );
			firmaServidor.write(this.numeroRegistro);
			firmaServidor.write(this.idPropietario.getBytes());
			firmaServidor.write(this.documento);
			firmaServidor.write(this.firma);
			signer.update(firmaServidor.toByteArray());
			this.firma_registrador=signer.sign();
			Debug.info("Se ha firmado el archivo: "+ this.nombreDocumento + " con un tamaño " +this.firma_registrador.length + " por el servidor.");
		}

	}
	public void cifrar(SecretKey key,String algoritmo,boolean cliente,IvParameterSpec iv) throws Exception {
		//Hay que cifrar this.documento
		Cipher cipher = Cipher.getInstance (algoritmo);

		if(iv!=null){
			cipher.init (Cipher.ENCRYPT_MODE, key, iv);
		}else{
			cipher.init (Cipher.ENCRYPT_MODE, key);
		}

		this.documento = cipher.doFinal (this.documento);
		this.cifrado = true;




		return;
	}
	public void descifrar(SecretKey key,String algoritmo,boolean cliente,IvParameterSpec iv) throws Exception {
		//Hay que descifrar this.documento

		Cipher cipher = Cipher.getInstance(algoritmo);

		if(iv!=null){
			cipher.init (Cipher.DECRYPT_MODE, key, iv);
		}else{
			cipher.init (Cipher.DECRYPT_MODE, key);
		}

		this.documento=cipher.doFinal (this.documento);
		this.cifrado = false;

		return;
	}

	public boolean verificar(java.security.cert.Certificate publicKey,String algoritmo,boolean cliente) throws Exception {
		Signature verifier=Signature.getInstance(algoritmo);
		verifier.initVerify(publicKey);
		verifier.update(this.documento);
		boolean resultado = false;

		if(cliente){

			resultado = verifier.verify(this.firma);
			Debug.info("Se ha comprobado la firma del cliente de: "+ this.nombreDocumento + " con resultado: "+ resultado);

		}else{
			resultado = verifier.verify(this.firma_registrador);
			Debug.info("Se ha comprobado la firma del registrador de: "+ this.nombreDocumento + " con resultado: "+ resultado);

		}

		return resultado;
	}


}
