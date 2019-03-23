
package top.zhumang.crypto.common.utils;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.utils.Utils;
import org.springframework.util.Base64Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;
/**
 *
 * @Author: zhumang
 * @Email: lake.lei@outlook.com
 * @Date: 2018-07-26
 * @Description:
 */
public class CipherApacheCBCUtils {
    /**
     * 加密方法/加密模式/填充方式，CBC是安全性好于ECB,适合传输长度长的报文,是SSL、IPSec的标准
     */
    static final String transform = "AES/CBC/PKCS5Padding";

    /**
     * Converts String to UTF8 bytes
     *
     * @param input the input string
     * @return UTF8 bytes
     */
    public  static byte[] getUTF8Bytes(String input) {
        return input.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 加密
     * @param text 需要加密的明文
     * @return 经过base64加密后的密文
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws ShortBufferException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encryptString(SecretKeySpec key,IvParameterSpec iv,String text) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        String encodedString = Base64Utils.encodeToString(encrypt(key,iv,getUTF8Bytes(text)));
        return encodedString;
    }

    /**
     *
     * @param key 密钥
     * @param iv 向量
     * @param data 待加密字节数组
     * @return
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws ShortBufferException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] encrypt(SecretKeySpec key,IvParameterSpec iv,byte[] data) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        Properties properties = new Properties();
        final ByteBuffer outBuffer;
        final int bufferSize = 1024;
        final int updateBytes;
        final int finalBytes;
        //Creates a CryptoCipher instance with the transformation and properties.
        try (CryptoCipher encipher = Utils.getCipherInstance(transform, properties)) {
            ByteBuffer inBuffer = ByteBuffer.allocateDirect(bufferSize);
            outBuffer = ByteBuffer.allocateDirect(bufferSize);
            inBuffer.put(data);
            inBuffer.flip(); // ready for the cipher to read it
            // Show the data is there
            // Initializes the cipher with ENCRYPT_MODE,key and iv.
            encipher.init(Cipher.ENCRYPT_MODE, key, iv);
            // Continues a multiple-part encryption/decryption operation for byte buffer.
            updateBytes = encipher.update(inBuffer, outBuffer);
            // We should call do final at the end of encryption/decryption.
            finalBytes = encipher.doFinal(inBuffer, outBuffer);

        }
        outBuffer.flip(); // ready for use as decrypt
        byte[] encoded = new byte[updateBytes + finalBytes];
        outBuffer.duplicate().get(encoded);
        return encoded;
    }

    /**
     * 解密
     * @param encodedString 经过base64加密后的密文
     * @return 明文
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws ShortBufferException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String dencryptString(SecretKeySpec key,IvParameterSpec iv,String encodedString) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        byte[]  bytes = dencrypt(key,iv,getUTF8Bytes(encodedString));
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     *
     * @param key
     * @param iv
     * @param data
     * @return
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws ShortBufferException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] dencrypt(SecretKeySpec key,IvParameterSpec iv,byte[] data) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        Properties properties = new Properties();
        final ByteBuffer outBuffer;
        final int bufferSize = 1024;
        ByteBuffer decoded = ByteBuffer.allocateDirect(bufferSize);
        //Creates a CryptoCipher instance with the transformation and properties.
        try (CryptoCipher decipher = Utils.getCipherInstance(transform, properties)) {
            decipher.init(Cipher.DECRYPT_MODE, key, iv);
            outBuffer = ByteBuffer.allocateDirect(bufferSize);
            outBuffer.put(data);
            outBuffer.flip();
            decipher.update(outBuffer, decoded);
            decipher.doFinal(outBuffer, decoded);
            decoded.flip(); // ready for use
        }
        final byte[] bytes = new byte[decoded.remaining()];
        decoded.get(bytes);
        return bytes;
    }

}