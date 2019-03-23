package top.zhumang.crypto.annotation;

import top.zhumang.crypto.common.dae.NoSupportEncryptTypeException;
import top.zhumang.crypto.common.dae.encryptor.Encryptor;
import top.zhumang.crypto.common.dae.encryptor.EncryptorFactory;
import top.zhumang.crypto.common.utils.FieldUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.util.List;
/**
 * @Author: zhumang
 * @Email: lake.lei@outlook.com
 * @Date: 2018-07-26
 * @Description:
 */
@Component
public class EncryptionAnnotationHandlerImpl implements AnnotationHandler {
    private final static Logger logger = LogManager.getLogger(AnnotationHandler.class);
    private static final EncryptorFactory factory = new EncryptorFactory();

    @Override
    public void handle(Object e){
        if(e instanceof List){
            List<Object> objects = (List<Object>) e;
            for(Object object:objects){
                try {
                    doEncryption(object);
                } catch (NoSupportEncryptTypeException e1) {
                    e1.printStackTrace();
                }
            }
        }else{
            try {
                doEncryption(e);
            } catch (NoSupportEncryptTypeException e1) {
                e1.printStackTrace();
            }
        }

    }

    private void doEncryption(Object e) throws NoSupportEncryptTypeException {
        Field[] fields = e.getClass().getDeclaredFields();
        for (Field field : fields) {
            if (hasEncryptionAnnotation(field)) {
                if (FieldUtils.isStringType(field)) {
                    handleStringEncryption(e, field);
                } else if (FieldUtils.isBytesBuff(field)) {
                    handleBytesBuff(e, field);
                } else {
                    throw new NoSupportEncryptTypeException(field.getType().getClass().getSimpleName());
                }
            }
        }
    }


    private void handleBytesBuff(Object o, Field field) {
        Encryption encryption = field.getAnnotation(Encryption.class);
        String key = encryption.key();
        byte[] key2bytes = new byte[0];
        if (StringUtils.isEmpty(key)){
            key2bytes = key.getBytes(Charset.forName("UTF-8"));
        }
        String encryptor = encryption.encryptor();
        try {
            Encryptor encryptor1 = factory.getEncrytor(encryptor);
            field.setAccessible(true);
            byte[] bytes = (byte[]) field.get(o);
            field.set(o, StringUtils.isEmpty(key) ? encryptor1.encrypt(bytes) : encryptor1.encrypt(bytes, key2bytes));
        } catch (Exception e) {
            logger.error("", e);
        } finally {
            field.setAccessible(false);
        }
    }

    private void handleStringEncryption(Object e, Field field) {
        Encryption encryption = field.getAnnotation(Encryption.class);
        field.setAccessible(true);
        try {
            String s = (String) field.get(e);
            if(!StringUtils.isEmpty(s)){
                field.set(e, bytesToStringBase64(!StringUtils.isEmpty(encryption.key()) ? factory.getEncrytor(encryption.encryptor()).encrypt(s.getBytes("UTF-8"), encryption.key().getBytes("UTF-8")) : factory.getEncrytor(encryption.encryptor()).encrypt(s.getBytes("UTF-8"))));
            }
        } catch (Exception ex) {
            logger.error(ex);
        } finally {
            field.setAccessible(false);
        }
    }

    private String bytesToStringBase64(byte[] srcs) {
        return Base64Utils.encodeToString(srcs);
    }

    private boolean hasEncryptionAnnotation(Field field) {
        return (null != field.getAnnotation(Encryption.class));
    }
}
