package hi.chyl.json;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AesUtil {

    private static final Integer PRIVATE_KEY_SIZE_BIT = 128;
    private static final Integer PRIVATE_KEY_SIZE_BYTE = 16;

    private static final String ENCRYPT_MODE_ECB = "ECB";

    private static final String _ENCRYPT_MODE = "CBC";

    public static String encrypt(String plainText,String secretKey){
        try {
            Cipher cipher = initParam(secretKey,1);
            byte[] bytePlainText = plainText.getBytes(StandardCharsets.UTF_8);
            byte[] byteCipherText = cipher.doFinal(bytePlainText);
            return Base64.getEncoder().encodeToString(byteCipherText);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String decrypt(String cipherText,String secretKey){
        try {
            Cipher cipher = initParam(secretKey,2);
            byte[] byteCipherText = Base64.getDecoder().decode(cipherText);
            byte[] bytePlainText = cipher.doFinal(byteCipherText);
            return new String(bytePlainText,StandardCharsets.UTF_8);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static Cipher initParam(String secretKey,int mode){
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(secretKey.getBytes());
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(PRIVATE_KEY_SIZE_BIT,secureRandom);
            byte[] raw = secretKey.getBytes();
            SecretKeySpec key = new SecretKeySpec(raw,"AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(secretKey.getBytes());
            cipher.init(mode,key,iv);
            return cipher;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String aesKey = "bbpavikxycptesrb";

        String encrypt = encrypt("{\"code\":0,\"data\":{\"bulletin\":false,\"subLive\":false,\"commentThumbUp\":false,\"commentCommit\":false},\"msg\":\"ok\"}", aesKey);
        System.out.println(encrypt);
        System.out.println(decrypt(encrypt, aesKey));
    }
}
