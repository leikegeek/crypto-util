package top.zhumang.crypto.common.utils;
import java.lang.reflect.Field;
/**
 *
 * @Author: zhumang
 * @Email: lake.lei@outlook.com
 * @Date: 2018-07-26
 * @Description:
 */
public class FieldUtils {

    public static boolean isStringType(Field field) {
        return field.getType().equals(String.class);
    }

    public static boolean isBytesBuff(Field field) {
        return field.getType().equals(byte[].class);
    }
}
