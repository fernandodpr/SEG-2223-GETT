package Client;

import java.io.*;
//import javax.cryto.*;
//import javax.cryto.spec.*;
import java.security.AlgorithmParameters;
import java.util.Scanner;
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
       System.out.println("3. Listar documentos\n\n\n");

       Scanner scan = new Scanner(System.in);
       String respuesta = scan.next();

       switch(respuesta){
         case "1":
          System.out.println("1. Enviar archivo al servidor.(registrar_documento)\n");
          break;
         case "2":
          System.out.println("2. Recibir documento. (recuperar_documento)\n");
          break;
         case "3":
          System.out.println("3. Listar documentos\n");
          break;
         default:
          System.out.println("Opcion incorrecta.\n\n");
          break;
       }
     }
   }
}
