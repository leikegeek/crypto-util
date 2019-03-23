package top.zhumang.crypto.common.dae.decryptor;

import top.zhumang.crypto.common.utils.CipherApacheCBCUtils;
import top.zhumang.crypto.common.utils.EnctryKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * @Author: zhumang
 * @Email: lake.lei@outlook.com
 * @Date: 2018/9/24 11:46
 * @Description:
 */
@Component
@Order(value = 1)
public class CBCDecryptor implements Decryptor,CommandLineRunner {
    private final static Logger logger = LogManager.getLogger(CBCDecryptor.class);
    private SecretKeySpec key ;
    /**
     * 固定16字节长度
     */
    private IvParameterSpec iv ;
    @Autowired
    private Environment environment;

    @Override
    public void run(String... args) throws Exception {
        if(StringUtils.isEmpty(EnctryKey.keyStr) || StringUtils.isEmpty(EnctryKey.ivStr)){
            EnctryKey.ivStr = environment.getProperty("ivStr");
            EnctryKey.keyStr = environment.getProperty("keyStr");
        }
        key = new SecretKeySpec(CipherApacheCBCUtils.getUTF8Bytes(EnctryKey.keyStr), "AES");
        iv = new IvParameterSpec(CipherApacheCBCUtils.getUTF8Bytes(EnctryKey.ivStr));
        logger.info("init CBCDecryptor success");
    }

    @Override
    public byte[] decrypt(byte[] plainObject) {
        return CBCDecryptor(plainObject);
    }

    @Override
    public byte[] decrypt(byte[] plainObject, byte[] key) {
        return CBCDecryptor(plainObject);
    }

    private byte[] CBCDecryptor(byte[] plainData) {
        byte[] data = new byte[0];
        try {
            data = CipherApacheCBCUtils.dencrypt(key,iv,plainData);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (ShortBufferException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return data;
    }
}
