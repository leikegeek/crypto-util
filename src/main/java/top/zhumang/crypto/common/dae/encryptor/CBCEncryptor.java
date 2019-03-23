package top.zhumang.crypto.common.dae.encryptor;

import top.zhumang.crypto.common.utils.CipherApacheCBCUtils;
import top.zhumang.crypto.common.utils.EnctryKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

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
@Order(value = 2)
public class CBCEncryptor implements Encryptor,CommandLineRunner {
    private final static Logger logger = LogManager.getLogger(CBCEncryptor.class);

    private SecretKeySpec key ;
    /**
     * 固定16字节长度
     */
    private IvParameterSpec iv ;

    @Override
    public void run(String... args) throws Exception {
        key = new SecretKeySpec(CipherApacheCBCUtils.getUTF8Bytes(EnctryKey.keyStr), "AES");
        iv = new IvParameterSpec(CipherApacheCBCUtils.getUTF8Bytes(EnctryKey.ivStr));
        logger.info("init CBCEncryptor success");
    }

    @Override
    public byte[] encrypt(byte[] plainObject) {
        return CBCEncryptor(plainObject);
    }

    @Override
    public byte[] encrypt(byte[] plainObject, byte[] key) {
        return CBCEncryptor(plainObject);
    }

    private byte[] CBCEncryptor(byte[] plainData) {
        byte[] data = new byte[0];
        try {
            data = CipherApacheCBCUtils.encrypt(key,iv,plainData);
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
