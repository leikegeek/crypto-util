两个注解搞定字段的加解密
## 快速上手
- 引入jar包,本工具类已经发布至maven官方仓库,直接引用即可,另外本工具依赖了apache的commons-crypto
  需要一并引入,示例如下:
```xml
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-crypto</artifactId>
            <version>1.0.0</version>
        </dependency>
        <dependency>
            <groupId>top.zhumang</groupId>
            <artifactId>crypto-util</artifactId>
            <version>0.0.1-SNAPSHOT</version>
        </dependency>
```
- springboot启动类加入对此工具类的扫描,使其正常初始化.
```java
@ComponentScan(basePackages = {"top.zhumang.crypto.common"})
```
 如果启动后看到如下信息说明初始化正常:
```text
[INFO] - top.zhumang.crypto.common.dae.decryptor.CBCDecryptor.run(CBCDecryptor.java:49) - init CBCDecryptor success
[INFO] - top.zhumang.crypto.common.dae.encryptor.CBCEncryptor.run(CBCEncryptor.java:41) - init CBCEncryptor success
[INFO] - top.zhumang.crypto.common.dae.decryptor.ECBDecryptor.run(ECBDecryptor.java:37) - init ECBDecryptor success
[INFO] - top.zhumang.crypto.common.dae.encryptor.ECBEncryptor.run(ECBEncryptor.java:29) - init ECBEncryptor success
``` 
- 设置加密密钥和偏移量
  目前对springboot项目支持较为优化,只需要在springboot的项目配置文件下加上以下两个
  配置变量即可:
```yaml
  # 加密密钥
  keyStr: 
  # 偏移量
  ivStr:
```
- 在字段上加注解
```text
对需要使用注解的字段加上注解,注解的值为加解密处理的实现类类名.该实现类需要继承
Encryptor 或 Decryptor 两个接口.分别是加密和解密的接口.本包默认提供四种实现类
分别为:CBCEncryptor(CBC模式的加密实现类),ECBEncryptor(ECB模式的加密实现类),
CBCDecryptor(CBC模式的解密实现类),ECBDecryptor(ECB模式的解密实现类)
```

示例:
```java
/**
* 对该字段进行CBC模式的加密解密
*/
@Decryption(decryptor="CBCDecryptor")
@Encryption(encryptor="CBCEncryptor")
private String email;
```

- 调用处理类进行加解密
示例:
```java
/**
* 作为类变量引入处理类
*/
AnnotationHandler encryptor = new EncryptionAnnotationHandlerImpl();
AnnotationHandler decryptor = new DecryptionAnnotationHandlerImpl();
...

User user = new User();
user.setEmail("lake.lei@outlook.com");
//加密对象
encryptor.handle(user);
//解密对象
decryptor.handle(user);
```
- 通过注解处理调用实现
上面一段代码如果放入到业务代码中,虽然只有三行但是依然是重复的机械代码.对此
我们可以写一个基于方法的注解和切面.在方法上加上注解然后让此方面被调用的时候
切面直接自动调用加解密的方法.
示例:
1.自定义注解
```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CryptorAnnotation {
    /**
     * 加解密注解 默认为空 不做处理
     * @return
     */
    String cryptoValue() default "";

}
```

2.切面
```java
/**
 * @author Lake
 * @description: 加解密切面
 * @date 2019/3/20
 */
@Aspect
@Component
public class CryptorAspect {
    private AnnotationHandler encryptor = new EncryptionAnnotationHandlerImpl();
    private AnnotationHandler decryptor = new DecryptionAnnotationHandlerImpl();
    private Logger logger = LogManager.getLogger(CryptorAspect.class);
    
    @Pointcut("@annotation(org.liezi.common.annotation.CryptorAnnotation)")
    public void cryptorPointCut() {
        
    }

    @Around("cryptorPointCut()")
    public Object around(ProceedingJoinPoint point) throws Throwable {
        /**
         * 获取目标方法基本参数
         */
        //目标方法签名
        MethodSignature signature = (MethodSignature) point.getSignature();
        Method method = signature.getMethod();
        //目标方法类名
        String className = point.getTarget().getClass().getName();
        //目标方法名
        String methodName = signature.getName();
        //目标方法
        CryptorAnnotation cryptorAnnotation = method.getAnnotation(CryptorAnnotation.class);
        //入参
        Object[] inParams = point.getArgs();
        /**
        * 获取注解的值
        * null表示不做处理
        */
        String cryptoValue = cryptorAnnotation.cryptoValue();
        //如果为ENC表示加密
        if(StringUtils.isNotEmpty(cryptoValue) && cryptoValue.equals("ENC")){
            //根据项目实际情况获取入参
            Object inParam = inParams[0];
            encryptor.handle(inParam);
        }
        /**
         * 执行目标方法
         */
        //返参
        Object result = new Object();
        String exceptionMsg = new String();
        try{
            result = point.proceed();
        }catch (Exception e){
            exceptionMsg = e.getMessage();
        }
        // TODO 解密处理
        //如果为DEC表示加密
        if(StringUtils.isNotEmpty(cryptoValue) && cryptoValue.equals("DEC")){
           //根据项目实际情况获取返参
           encryptor.handle(result);
        }
        return result;
    }
}
```
3. 使用注解
```java
  @CryptorAnnotation("ENC")
  @ResponseBody
  public Map<String,Object> add(@RequestBody User user){
     //业务代码
  }
```
这样在业务代码中一个代码即可搞定针对入参的部分类的加密解密的功能了.