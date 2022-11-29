import java.io.*;


public class  Paquete implements Serializable {
    private Archivo archivo; //con el documento cifrado por clave K
    private String instruccion;
    private byte[] claveK; //Cifrado por la calve pública del cliente o servidor
    

    public Paquete(Archivo archivo, String instruccion, byte[] claveK) {
        this.archivo=archivo;
        this.instruccion=instruccion;
        this.claveK=claveK;
    }
}