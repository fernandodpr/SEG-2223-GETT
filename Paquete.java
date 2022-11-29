import java.io.*;


public class  Paquete implements Serializable {
    private Archivo archivo; //con el documento cifrado por clave K
    private String instruccion;



    private byte[] claveK;
	public Archivo getArchivo() {
		return this.archivo;
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
	public byte[] getClaveK() {
		return this.claveK;
	}

	public void setClaveK(byte[] claveK) {
		this.claveK = claveK;
	}
 //Cifrado por la calve pública del cliente o servidor
    

    public Paquete(Archivo archivo, String instruccion, byte[] claveK) {
        this.archivo=archivo;
        this.instruccion=instruccion;
        this.claveK=claveK;
    }
}