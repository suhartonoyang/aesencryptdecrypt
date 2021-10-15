import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import aesencryptdecrypt.service.EncryptorAesGcm;
import aesencryptdecrypt.service.EncryptorAesGcmPassword;
import aesencryptdecrypt.utils.CryptoUtils;

public class Main {

	private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
	private static final int TAG_LENGTH_BIT = 128;
	private static final int IV_LENGTH_BYTE = 12;
	private static final int AES_KEY_BIT = 256;
	private static final Charset UTF_8 = StandardCharsets.UTF_8;
	

	// encryptor aes gcm
//	public static void main(String[] args) throws Exception {
//		String OUTPUT_FORMAT = "%-30s:%s";
//		
//		String pText = "suhartono14";
//		
//		// encrypt and decrypt need the same key
//		// get aes 256 bits (32 bytes) key
//		SecretKey secretKey = CryptoUtils.getAESKey(AES_KEY_BIT);
//		
//		// encrypt and decrypt need the same IV.
//        // AES-GCM needs IV 96-bit (12 bytes)
//        byte[] iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE);
//
//        byte[] encryptedText = EncryptorAesGcm.encryptWithPrefixIV(pText.getBytes(UTF_8), secretKey, iv);
//        
//        System.out.println("\n------ AES GCM Encryption ------");
//        System.out.println(String.format(OUTPUT_FORMAT, "Input (plain text)", pText));
//        System.out.println(String.format(OUTPUT_FORMAT, "Key (hex)", CryptoUtils.hex(secretKey.getEncoded())));
//        System.out.println(String.format(OUTPUT_FORMAT, "IV  (hex)", CryptoUtils.hex(iv)));
//        System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (hex) ", CryptoUtils.hex(encryptedText)));
//        System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (hex) (block = 16)", CryptoUtils.hexWithBlockSize(encryptedText, 16)));
//
//        System.out.println("\n------ AES GCM Decryption ------");
//        System.out.println(String.format(OUTPUT_FORMAT, "Input (hex)", CryptoUtils.hex(encryptedText)));
//        System.out.println(String.format(OUTPUT_FORMAT, "Input (hex) (block = 16)", CryptoUtils.hexWithBlockSize(encryptedText, 16)));
//        System.out.println(String.format(OUTPUT_FORMAT, "Key (hex)", CryptoUtils.hex(secretKey.getEncoded())));
//
//        String decryptedText = EncryptorAesGcm.decryptWithPrefixIV(encryptedText, secretKey);
//
//        System.out.println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", decryptedText));
//
//	}
	
	
	// encryptor aes gcm password
	public static void main(String[] args) throws Exception {

        String OUTPUT_FORMAT = "%-30s:%s";
        String PASSWORD = "this is a password";
        String pText = "suhartono14";

        String encryptedTextBase64 = EncryptorAesGcmPassword.encrypt(pText.getBytes(UTF_8), PASSWORD);

        System.out.println("\n------ AES GCM Password-based Encryption ------");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (plain text)", pText));
        System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (base64) ", encryptedTextBase64));

        System.out.println("\n------ AES GCM Password-based Decryption ------");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (base64)", encryptedTextBase64));

        String decryptedText = EncryptorAesGcmPassword.decrypt(encryptedTextBase64, PASSWORD);
        System.out.println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", decryptedText));
        
        System.out.println(decryptedText);

    }

}
