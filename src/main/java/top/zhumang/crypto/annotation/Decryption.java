package top.zhumang.crypto.annotation;

import java.lang.annotation.*;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
public @interface Decryption {
    String decryptor();

    String key() default "";
}
