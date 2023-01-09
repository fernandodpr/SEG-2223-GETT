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



//TEST
import java.nio.charset.Charset;
import java.util.Random;


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
	public void cifrar(SecretKey secretKey,String algoritmo) throws Exception {
		if(!this.cifrado){
			//Hay que cifrar this.documento simetrico
			Cipher cipher = Cipher.getInstance (algoritmo);
			byte[] initializationVector= new byte[16];
			Debug.warn("El tamaño de los datos es "+ this.documento.length);
			//SecureRandom secureRandom= new SecureRandom();
			//secureRandom.nextBytes(initializationVector);
			IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
			cipher.init(Cipher.ENCRYPT_MODE,secretKey,ivParameterSpec);
			this.documento = cipher.doFinal (this.documento);
			this.cifrado = true;
		}
		return;
	}
	//opmode - the operation mode of this cipher (this is one of the following: ENCRYPT_MODE, DECRYPT_MODE, WRAP_MODE or UNWRAP_MODE)
	//   ALGORITMO:  algorithm/mode/padding

	//Algoritmos usados:
		//Asimetrico:
		// ###################################clave K
		//Simetrico de archivo: 
	public void descifrar(SecretKey secretKey,String algoritmo) throws Exception {
		//Hay que descifrar this.documento simetrico
		if(this.cifrado){
			Cipher cipher = Cipher.getInstance(algoritmo);
			byte[] initializationVector= new byte[16];
			//SecureRandom secureRandom= new SecureRandom();
			//secureRandom.nextBytes(initializationVector);
			IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
			this.documento=cipher.doFinal(this.documento);
			this.cifrado = false;
		}
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
			Debug.info("La firma del registrador tiene un tamaño de: "+this.firma_registrador.length);
			resultado = verifier.verify(this.firma_registrador);
			Debug.info("Se ha comprobado la firma del registrador de: "+ this.nombreDocumento + " con resultado: "+ resultado);
		}

		return resultado;
	}

	public void guardaDocumento(String filepath){
		try {
			//TODO: Crear el filepath
			if(filepath == null) {
				String aux = this.getIdPropietario().split(",")[0];
				aux = aux.substring(3);
				filepath = String.valueOf(this.getNumeroRegistro())+"_"+aux+".sig.cif";
			}
			filepath=filepath.toLowerCase();
			FileOutputStream fileOut = new FileOutputStream(filepath);
			ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
			objectOut.writeObject(this);
			Debug.warn("El tamaño de los datos es "+ this.documento.length);
			objectOut.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	public void guardaDocumentoDatos(String filepath){
		try {
			//TODO: Crear el filepath
			
			FileOutputStream fileOut = new FileOutputStream(filepath);
			
			fileOut.write(this.documento);
			fileOut.close();
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
