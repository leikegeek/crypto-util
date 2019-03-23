package top.zhumang.crypto.common.utils;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @Author: zhumang
 * @Email: lake.lei@outlook.com
 * @time 2018年10月5日 下午10:02:05
 */
public class EnctryKey {
   
	private EnctryKey(){}

	public static SecretKeySpec key ;
	public static IvParameterSpec iv ;
	/**
	 * 秘钥数据
	 */
	public static String keyStr;

	public static String ivStr;

	public static void setKeyStr(String inParam){
		keyStr = inParam;
	}

	public static void setIvStr(String inParam){ ivStr = inParam; }

}
