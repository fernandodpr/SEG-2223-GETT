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

	public Archivo getArchivo() {
		return this.archivo;
	}

	public void setClaveK(SecretKey clave){
		this.claveK=clave.getEncoded();

		return;
	}
	public SecretKey getclaveK(){
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
	public void descifrarClaveK(PublicKey publicKey,String provider,String algoritmo,String algoritmobase,boolean cliente) throws Exception {
		//Hay que descifrar this.claveK
	}

    public Paquete(Archivo archivo, String instruccion, byte[] claveK) {
        this.archivo=archivo;
        this.instruccion=instruccion;
	}
	public Paquete() {
        
    }
}