package top.zhumang.crypto.common.dae.encryptor;
public interface Encryptor
{
    byte[] encrypt(byte[] plainObject);

    byte[] encrypt(byte[] plainObject, byte[] key);
}
