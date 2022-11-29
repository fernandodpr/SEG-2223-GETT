public class  Archivo{
    private String numeroRegistro;
    private String timestamp;
    private byte[] documento;
    private byte[] firma;
    private byte[] firma_rgistrador;

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

	public byte[] getFirma() {
		return this.firma;
	}

	public void setFirma(byte[] firma) {
		this.firma = firma;
	}

	public byte[] getFirma_rgistrador() {
		return this.firma_rgistrador;
	}

	public void setFirma_rgistrador(byte[] firma_rgistrador) {
		this.firma_rgistrador = firma_rgistrador;
	}


    public Archivo() {
        
    }
    
}