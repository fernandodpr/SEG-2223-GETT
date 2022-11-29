import java.io.*;
import java.util.Date;

public class  Archivo implements Serializable {
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
		this.timestamp=String timeStamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
		this.documento=documento;
		this.cifrado=false;
		this.nombreDocumento=nombreDocumento;
		this.firma=null;
		this.firma_registrador=null;
    }
    
}