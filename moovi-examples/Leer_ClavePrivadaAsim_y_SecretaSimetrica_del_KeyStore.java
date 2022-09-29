
//  **************   LEER LA CLAVE PRIVADA  **************************
// Obtener la clave privada del keystore

// IMPORTANTE: No olvidar incluir en la cabecera el import	"import java.security.*;"


char[]  key_password = "111111".toCharArray();

KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
    ks.getEntry("privateKeyAlias", new KeyStore.PasswordProtection(key_password));

PrivateKey myPrivateKey = pkEntry.getPrivateKey();


//  **************   LEER LA CLAVE SECRETA  **************************

char[]  key_password = "111111".toCharArray();

KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry)
	        ks.getEntry("k_registrador", new KeyStore.PasswordProtection(key_password));

byte[]  kreg_raw = pkEntry.getSecretKey().getEncoded();
SecretKeySpec kreg = new SecretKeySpec(kreg_raw, "AES");
