package BibliotecaSEG;

/******************************************************************************
 Nombre: Cifrar_Descifrar_Asimetrico_SunJCE_v1.0

 Descripcion:
                 Codigo JAVA para cifrar y descifrar ASIMETRICO un fichero de texto o binario

 Notas de uso:
                 1. Solo valido para algoritmo RSA 
                 2. Permite medir el tiempo y velocidad de cifrado.

 Fecha:  12/12/2018
 Autor: 
                 Francisco J. Fernandez Masaguer
                 ETSI TELECOMUNACION VIGO
                 Departamento Ingenieria Telematica
                 email: francisco.fernandez@det.uvigo.es

 Asignatura:
                 SEGURIDAD.  3º GETT.   Curso  2018/2019. 

 *****************************************************************************/

import java.io.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CifradoASimetrico {

        static String provider = "SunJCE";
        
        public static void main(String[] args) throws Exception {

                FileInputStream         ftextoclaro     = new FileInputStream(Config.dir + "leopardo_nieves.jpg");              
                FileOutputStream        ftextocifrado   = new FileOutputStream(Config.dir  + "textocifrado");

                String algoritmo                = "RSA";
                String transformacion1  = "/ECB/PKCS1Padding"; //Relleno de longitud fija de 88 bits (11 bytes)
                String transformacion2  = "/ECB/OAEPPadding"; // Este relleno tiene una longitud mayor y es variable
                int longclave                   = 1024;               // NOTA -- Probar a subir este valor e ir viendo como 
                                                              //         disminuye significativamente la velocidad de descifrado 
                int longbloque;
                long t, tbi, tbf;           // tiempos totales y por bucle
                double lf;                              // longitud del fichero

                byte bloqueclaro[]              = new byte[(longclave/8) - 11]; // *** NOTA: Calculo solo valido para relleno PKCS1Padding ****
                byte bloquecifrado[]    = new byte[2048];
                
                /************************************************************
                 * Generar  pareja de claves para prueba 
                 ************************************************************/
                // Crea generador de claves

                KeyPairGenerator keyPairGen;
                keyPairGen = KeyPairGenerator.getInstance(algoritmo);

                keyPairGen.initialize(longclave);

                // Generamos un par de claves (publica y privada)
                KeyPair keypair = keyPairGen.genKeyPair();
                PrivateKey privateKey = keypair.getPrivate();
                PublicKey  publicKey = keypair.getPublic();
                
                /************************************************************
                 * CIFRAR
                 ************************************************************/
                System.out.println("*** INICIO CIFRADO " + algoritmo + "-" + longclave
                                + " ************");

                Cipher cifrador = Cipher.getInstance(algoritmo + 
                                                             transformacion1);

                // Se cifra con la modalidad opaca de la clave

                cifrador.init(Cipher.ENCRYPT_MODE, publicKey);


                // Datos para medidas de velocidad cifrado
                t = 0; lf = 0; tbi = 0;  tbf = 0;

                while ((longbloque = ftextoclaro.read(bloqueclaro)) > 0) {

                        lf = lf + longbloque;

                        tbi = System.nanoTime();
                        
                        bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
                        bloquecifrado = cifrador.doFinal();

                        tbf = System.nanoTime();
                        t = t + tbf - tbi;

                        ftextocifrado.write(bloquecifrado);
                }
                
                // Escribir resultados velocidad cifrado

                System.out.println("*** FIN CIFRADO " + algoritmo + "-" + longclave
                                                                                          + " Provider: " + provider);
                System.out.println("Bytes  cifrados = " + (int) lf);
                System.out.println("Tiempo cifrado  = " + t / 1000000 + " mseg");
                System.out.println("Velocidad       = " + (lf * 8 * 1000) / t + " Mpbs");

                // Cerrar ficheros
                ftextocifrado.close();
                ftextoclaro.close();

        
                // *****************************************************************************
                // DESCIFRAR
                // *****************************************************************************
                FileInputStream  ftextocifrado2 = new FileInputStream( Config.dir  + "textocifrado");
                FileOutputStream ftextoclaro2 = new FileOutputStream( Config.dir  + "textoclaro2");

                byte bloquecifrado2[] = new byte[longclave/8];
                byte bloqueclaro2[] = new byte[512];  // *** Buffer sobredimensionado ***

                System.out.println("\n*** INICIO DESCIFRADO " + algoritmo + "-" + longclave + " ************");

                Cipher descifrador = Cipher.getInstance(algoritmo + 
                                                                transformacion1,
                                                                                                provider);

                descifrador.init(Cipher.DECRYPT_MODE, privateKey);

                
                // Datos para medidas de velocidad descifrado
                t = 0; lf = 0; tbi = 0;  tbf = 0;

                while ((longbloque = ftextocifrado2.read(bloquecifrado2)) > 0) {
                        
                        lf = lf + longbloque;

                        tbi = System.nanoTime();

                        bloqueclaro2 = descifrador.update(bloquecifrado2, 0, longbloque);
                        bloqueclaro2 = descifrador.doFinal();

                        tbf = System.nanoTime();
                        t = t + tbf - tbi;

                        ftextoclaro2.write(bloqueclaro2);
                }


                ftextocifrado2.close();
                ftextoclaro2.close();

                // Escribir resultados medida velocidad descifrado

                System.out.println("*** FIN DESCIFRADO " + algoritmo + "-" + longclave
                                                                                          + " Provider: " + provider);
                System.out.println("Bytes  descifrados = " + (int) lf);
                System.out.println("Tiempo descifrado  = " + t / 1000000 + " mseg");
                System.out.println("Velocidad = " + (lf * 8 * 1000) / t + " Mpbs");

        }

}
