package top.zhumang.crypto.common.dae.decryptor;

public interface Decryptor {
    byte[] decrypt(byte[] encryptObject);

    byte[] decrypt(byte[] encryptObject, byte[] key);
}
