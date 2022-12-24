import java.io.*;


public class  Paquete implements Serializable {
    private Archivo archivo; //con el documento cifrado por clave K
	private String instruccion;
	private KeyPair claveK;

	public Archivo getArchivo() {
		return this.archivo;
	}

	public void setclaveK(KeyPair clave){
		this.claveK=clave;
		return;
	}
	public KeyPair getclaveK(){
		return claveK;
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
	public void cifrarClaveK(PrivateKey privateKey,String provider,String algoritmo,String algoritmo_base,boolean cliente) throws Exception {
		//Hay que cifrar this.claveK
	}
	public void descifrarClaveK(PublicKey publicKey,String provider,String algoritmo,String algoritmo_base,boolean cliente) throws Exception {
		//Hay que descifrar this.claveK
	}

    public Paquete(Archivo archivo, String instruccion, byte[] claveK) {
        this.archivo=archivo;
        this.instruccion=instruccion;
    }
}