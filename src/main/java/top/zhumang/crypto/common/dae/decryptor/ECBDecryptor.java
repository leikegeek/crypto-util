package top.zhumang.crypto.common.dae.decryptor;

import top.zhumang.crypto.common.utils.EnctryKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

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
@Order(value = 3)
public class ECBDecryptor implements Decryptor,CommandLineRunner {
    private final static Logger logger = LogManager.getLogger(Decryptor.class);
    private String secretKey;
    @Autowired
    private Environment environment;
    @Override
    public void run(String... args) throws Exception {
        if(StringUtils.isEmpty(EnctryKey.keyStr) || StringUtils.isEmpty(EnctryKey.ivStr)){
            EnctryKey.keyStr = environment.getProperty("keyStr");
        }
        secretKey = EnctryKey.keyStr;
        logger.info("init ECBDecryptor success");
    }
    @Override
    public byte[] decrypt(byte[] plainObject) {
        return ECBDecryptor(plainObject, secretKey.getBytes(Charset.forName("UTF-8")));
    }

    @Override
    public byte[] decrypt(byte[] plainObject, byte[] key) {
        return ECBDecryptor(plainObject, key);
    }

    private byte[] ECBDecryptor(byte[] plainData, byte[] key) {
        byte[] data = new byte[0];
        try {
            Cipher ecbCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            byte[] keys = new byte[16];
            System.arraycopy(key, 0, keys, 0, key.length > keys.length ? keys.length : key.length);
            SecretKey secretKey = new SecretKeySpec(keys, "AES");
            ecbCipher.init(Cipher.DECRYPT_MODE, secretKey, new SecureRandom());
            data = ecbCipher.doFinal(plainData);
        } catch (Exception e) {
            logger.error("something horrible happend ", e);
        }
        return data;
    }
}
