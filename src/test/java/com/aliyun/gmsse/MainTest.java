package com.aliyun.gmsse;

import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import org.junit.Assert;
import org.junit.Test;

import cn.gmssl.jce.skf.SKF;


public class MainTest {
    @Test
    public void test() throws IOException, NoSuchAlgorithmException, KeyManagementException {
        GMProvider provider = new GMProvider();
        SKF key = new SKF();
        key.login("C:\\Windows\\System32\\InterPass3000_YNRCC_CSP11.dll", "a12345678");
        KeyManager[] keys = {key};
        TrustAllManager3[] trust = { new TrustAllManager3() };
        SSLContext sc = SSLContext.getInstance("TLS", provider);
        sc.init(keys, trust, null);
        SSLSocketFactory ssf = sc.getSocketFactory();

        //URL serverUrl = new URL("https://sm2test.ovssl.cn/");
        URL serverUrl = new URL("https://ebank.ynrcc.com:6443/eweb/");
        //URL serverUrl = new URL("https://192.168.48.101:6443/");
        //URL serverUrl = new URL("https://demo.gmssl.cn:1443");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // set SSLSocketFactory
        conn.setSSLSocketFactory(ssf);
        conn.connect();
        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", conn.getCipherSuite());
    }
}

class TrustAllManager3 implements X509TrustManager
{
   private X509Certificate[] issuers;

   public TrustAllManager3()
   {
       this.issuers = new X509Certificate[0];
   }

   public X509Certificate[] getAcceptedIssuers()
   {
       return issuers ;
   }

   public void checkClientTrusted(X509Certificate[] chain, String authType)
   {}

   public void checkServerTrusted(X509Certificate[] chain, String authType)
   {}
}
