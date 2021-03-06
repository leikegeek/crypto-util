package top.zhumang.crypto.common.dae.decryptor;

import top.zhumang.crypto.common.dae.NoDeclearEncryptMethodException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.TreeMap;

/**
 * @Author: zhumang
 * @Email: lake.lei@outlook.com
 * @Date: 2018-07-26
 * @Description:
 */
@Component
public class DecryptorFactory implements ApplicationContextAware,InitializingBean {
    private final static Logger logger = LogManager.getLogger(DecryptorFactory.class);
    private static final Map<String, Decryptor> decryptorMap = new TreeMap<>();
    private ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    /**
     * 获取接口实现类的所有bean，并按自己定的规则放入map中
     * @throws Exception
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        Map<String, Decryptor> beanMap = applicationContext.getBeansOfType(Decryptor.class);
        for(Map.Entry<String, Decryptor> entry : beanMap.entrySet()){
            registerDecryptor(entry.getKey(),entry.getValue());
        }
        logger.info("Decryptor Initial successful");
    }

    private static void registerDecryptor(String name, Decryptor decryptor) {
        decryptorMap.put(name, decryptor);
    }

    public Decryptor getDecrytor(String encryWay)
            throws NoDeclearEncryptMethodException {
        Decryptor encryptor = decryptorMap.get(encryWay);
        if (null != encryptor) {
            return encryptor;
        }
        throw new NoDeclearEncryptMethodException();
    }


}
