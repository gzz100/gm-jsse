package cn.gmssl.jce.skf;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;

public abstract class IKeyManager implements KeyManager {
    public abstract X509Certificate getCert(int var1)  throws CertificateException;

    public abstract byte[] doSign(byte[] var1, int var2, int var3);
}

