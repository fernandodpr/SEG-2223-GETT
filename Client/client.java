package Client;

import java.io.*;
//import javax.cryto.*;
//import javax.cryto.spec.*;
import java.security.AlgorithmParameters;
import java.util.*;
///faltan imports

//se pueden separar las clases y archivos

public class client {
   public static void main(String args[]){
     int default_serverport=5060;
     String server_ip_add="localhost";

     while(true){
       System.out.println("\n\n\n¿Que desea hacer?\n");
       System.out.println("1. Enviar archivo al servidor.(registrar_documento)\n");
       System.out.println("2. Recibir documento. (recuperar_documento)\n");
       System.out.println("3. Listar documentos. (listar_documentos)\n");
       System.out.println("S. Salir. \n\n\n");

       Scanner scan = new Scanner(System.in);
       String respuesta = scan.next();

       switch(respuesta){
         case "1":
          System.out.println("1. Enviar archivo al servidor.(registrar_documento)\n");
          registrar_documento();
          break;
         case "2":
          System.out.println("2. Recibir documento. (recuperar_documento)\n");
          recuperar_documento();
          break;
         case "3":
          System.out.println("3. Listar documentos (listar_documentos)\n");
          listar_documentos();
          break;
         case "S":
         case "s":
          System.out.println("S. Salir.\n");
          System.exit(0);
          break;
         default:
          System.out.println("Opcion incorrecta.\n\n");
          break;
       }
     }
   }


  private static void registrar_documento() throws Exception {

  }

  private static void recuperar_documento(){

  }


  private static void listar_documentos(){

  }

}
