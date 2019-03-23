package top.zhumang.crypto.common.dae.encryptor;

import top.zhumang.crypto.common.utils.EnctryKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.SecureRandom;
/**
 * @Author: zhumang
 * @Email: lake.lei@outlook.com
 * @Date: 2018-07-26
 * @Description:
 */
@Component
@Order(value = 4)
public class ECBEncryptor implements Encryptor,CommandLineRunner {
    private final static Logger logger = LogManager.getLogger(ECBEncryptor.class);
    private String secretKey;
    @Override
    public void run(String... args) throws Exception {
        secretKey = EnctryKey.keyStr;
        logger.info("init ECBEncryptor success");
    }

    @Override
    public byte[] encrypt(byte[] plainObject) {
        return ECBEncryptor(plainObject, secretKey.getBytes(Charset.forName("UTF-8")));
    }

    @Override
    public byte[] encrypt(byte[] plainObject, byte[] key) {
        return ECBEncryptor(plainObject, key);
    }

    private byte[] ECBEncryptor(byte[] plainData, byte[] key) {
        byte[] data = new byte[0];
        try {
            Cipher ecbCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            byte[] keys = new byte[16];
            System.arraycopy(key, 0, keys, 0, key.length > keys.length ? keys.length : key.length);
            SecretKey secretKey = new SecretKeySpec(keys, "AES");
            ecbCipher.init(Cipher.ENCRYPT_MODE, secretKey, new SecureRandom());
            data = ecbCipher.doFinal(plainData);
        } catch (Exception e) {
            logger.error("something horrible happend ", e);
        }
        return data;
    }
}
