import java.io.*;
import java.net.*;

public class  server{
    private ServerSocket server = null;


    public static void main(String[] args) throws Exception {
        Socket socket;
	
		// accept a connection
		try{
            socket = server.accept();
        }catch (IOException e) {
		    System.out.println("Class Server died: " + e.getMessage());
		    e.printStackTrace();
		    return;
		}

        try{
            // Crea dos canales de salida, sobre el socket
			//		- uno binario  (rawOut)
			//		- uno de texto (out)
			
			OutputStream rawOut = socket.getOutputStream();
	
		    PrintWriter out = new PrintWriter(
										new BufferedWriter(
											new OutputStreamWriter(rawOut)));
            try{
				BufferedReader socketin =
				    new BufferedReader(
					new InputStreamReader(socket.getInputStream()));
				while(!socketin.ready()){
					
				}
				System.out.print(socketin.getMessage);


			}catch(Exception e){
				e.printStackTrace();
			}
        
		    

        }catch (IOException e){

        }
    }
}