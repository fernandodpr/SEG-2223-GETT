import java.io.*;
import java.util.Date;
import java.text.SimpleDateFormat;

import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.lang.*;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.Files;

public class  Archivo implements Serializable  {
	private int numeroRegistro;
	private String idPropietario;
	private String timestamp;
    private byte[] documento;  //esto se guarda cifardo
    private boolean cifrado;
    private String nombreDocumento;
    private byte[] firma;
    private byte[] firma_registrador;

	public String getIdPropietario() {
		return this.idPropietario;
	}

	public void setIdPropietario(String idPropietario) {
		this.idPropietario = idPropietario;
	}
;


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
	public void descifrar(SecretKey key,String algoritmo,boolean cliente,IvParameterSpec iviDono) throws Exception {
		//Hay que descifrar this.documento
		IvParameterSpec iv = new IvParameterSpec(new byte[16]);
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
		boolean resultado = false;

		if(cliente){
			verifier.update(this.documento);
			resultado = verifier.verify(this.firma);
			Debug.info("Se ha comprobado la firma del cliente de: "+ this.nombreDocumento + " con resultado: "+ resultado);

		}else{
			ByteArrayOutputStream firmaServidor = new ByteArrayOutputStream( );
			firmaServidor.write(this.numeroRegistro);
			firmaServidor.write(this.idPropietario.getBytes());
			firmaServidor.write(this.documento);
			firmaServidor.write(this.firma);
			verifier.update(firmaServidor.toByteArray());
			resultado = verifier.verify(this.firma_registrador);
			Debug.info("Se ha comprobado la firma del registrador de: "+ this.nombreDocumento + " con resultado: "+ resultado);
		}

		return resultado;
	}

	public String getHash() {
		
		StringBuilder hexString = new StringBuilder(2 * this.documento.length);
		for (int i = 0; i < this.documento.length; i++) {
			
			String hex = Integer.toHexString(0xff & this.documento[i]);
			if(hex.length() == 1) {
				hexString.append('0');
			}
			hexString.append(hex);
		}
		return hexString.toString();
		//Fuente: https://www.baeldung.com/sha-256-hashing-java
	}
	public void guardaDocumento(String filepath){
		try {
			//TODO: Crear el filepath
			if(filepath == null) filepath =String.valueOf(this.getNumeroRegistro())+"_"+this.getIdPropietario()+".sig.cif";
			
			filepath=filepath.toLowerCase();
			
			FileOutputStream fileOut = new FileOutputStream(filepath);
			ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
			objectOut.writeObject(this);
			objectOut.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public Archivo(Path documentPath){
		try {
			FileInputStream fis = new FileInputStream(documentPath.toFile());
		   	ObjectInputStream ois = new ObjectInputStream(fis);
			Archivo input = (Archivo) ois.readObject();
			this.numeroRegistro=input.getNumeroRegistro();
			this.idPropietario=input.getIdPropietario();
			this.timestamp=input.getTimestamp();
			this.documento=input.getDocumento();  //esto se guarda cifardo
			this.cifrado=input.isCifrado();
			this.nombreDocumento=input.getNombreDocumento();
			this.firma=input.getFirma();
			this.firma_registrador=input.getFirma_registrador();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return;

	}
}
