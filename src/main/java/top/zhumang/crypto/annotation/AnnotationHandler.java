package top.zhumang.crypto.annotation;
/**
 * @Author: zhumang
 * @Email: lake.lei@outlook.com
 * @Date: 2018-07-26
 * @Description:
 */
public interface AnnotationHandler {
    /**
     * handle every Annotation
     * the implement should declear what dose it handle
     * such as
     *
     * @param e
     */
    void handle(Object e);
}
