# SEG-2022-GETT
Materia Seguridad GETT. Curso 2022-23

El programa está conformado por dos partes, cliente y servidor. En lineas generales el programa es una "nube de ficheros" con mecanismos de firma y de cifrado de los documentos
### El cliente:
Firma el fichero, lo encripta simetricamente con clave aleatoria, encripta de forma asimétrica con la clave pública del servidor, lo envía.
Cuando solicita un fichero de vuelta comprueba la firma del servidor y checksum para evitar modificaciones.
### El servidor
Cuando recibe un archivo, desencripta y comprueba firmas del cliente, encripta previo almacenamiento.
Para enviar un archivo solicitado desencripta el fichero almacenado, firma y envía.


## Autoría
- Juan Bargiela Souto
- Pedro Blanco Casal
- Fernando de Peroy Rodríguez
