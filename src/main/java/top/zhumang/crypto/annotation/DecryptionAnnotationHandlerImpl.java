package top.zhumang.crypto.annotation;


import top.zhumang.crypto.common.dae.NoSupportEncryptTypeException;
import top.zhumang.crypto.common.dae.decryptor.Decryptor;
import top.zhumang.crypto.common.dae.decryptor.DecryptorFactory;
import top.zhumang.crypto.common.utils.FieldUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * @Author: zhumang
 * @Email: lake.lei@outlook.com
 * @Date: 2018-07-26
 * @Description:
 */
@Component
public class DecryptionAnnotationHandlerImpl implements AnnotationHandler {

    private static final DecryptorFactory factory = new DecryptorFactory();
    private static final Logger logger = LogManager.getLogger(DecryptionAnnotationHandlerImpl.class);

    @Override
    public void handle(Object e){
        if(e instanceof List){
            List<Object> objects = (List<Object>) e;
            for(Object object:objects){
                try {
                    doDecrption(object);
                } catch (NoSupportEncryptTypeException e1) {
                    e1.printStackTrace();
                }
            }
        }else{
            try {
                doDecrption(e);
            } catch (NoSupportEncryptTypeException e1) {
                e1.printStackTrace();
            }
        }
    }

    public void doDecrption(Object e) throws NoSupportEncryptTypeException {
        Field[] fields = e.getClass().getDeclaredFields();
        for (Field field : fields) {
            if (hasDecryptionAnnotation(field)) {
                if (FieldUtils.isStringType(field)) {
                    handleStringDecryption(e, field);
                } else if (FieldUtils.isBytesBuff(field)) {
                    handleBytesBuff(e, field);
                } else {
                    throw new NoSupportEncryptTypeException(field.getType().getClass().getSimpleName());
                }
            }
        }
    }

    private boolean hasDecryptionAnnotation(Field field) {
        return (null != field.getAnnotation(Decryption.class));
    }

    private void handleBytesBuff(Object o, Field field) {
        Decryption decryption = field.getAnnotation(Decryption.class);
        String key = decryption.key();
        byte[] key2bytes = new byte[0];
        if(!StringUtils.isEmpty(key)){
            key2bytes = key.getBytes(Charset.forName("UTF-8"));
        }
        field.setAccessible(true);
        try {
            Decryptor decryptor = factory.getDecrytor(decryption.decryptor());
            byte[] s = (byte[]) field.get(o);
            field.set(o, StringUtils.isEmpty(key) ? decryptor.decrypt(s) : decryptor.decrypt(s, key2bytes));
        } catch (Exception ex) {
            logger.error("", ex);
        } finally {
            field.setAccessible(false);
        }
    }

    private void handleStringDecryption(Object e, Field field){
        Decryption decryption = field.getAnnotation(Decryption.class);
        field.setAccessible(true);
        try {
            Decryptor decryptor = factory.getDecrytor(decryption.decryptor());
            String s = (String) field.get(e);
            if(!StringUtils.isEmpty(s)){
                field.set(e,new String(!StringUtils.isEmpty(decryption.key()) ? decryptor.decrypt(toByteBase64(s), decryption.key().getBytes(Charset.forName("UTF-8"))) : decryptor.decrypt(toByteBase64(s)), Charset.forName("UTF-8")));
            }
        } catch (Exception ex) {
            logger.error("", ex);
        } finally {
            field.setAccessible(false);
        }
    }

    private byte[] toByteBase64(String hexString) {
        return Base64Utils.decode(hexString.getBytes(StandardCharsets.UTF_8));
    }


}
