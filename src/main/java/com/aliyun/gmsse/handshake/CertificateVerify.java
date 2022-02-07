package com.aliyun.gmsse.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import com.aliyun.gmsse.crypto.Crypto;
import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;

import cn.gmssl.jce.skf.IKeyManager;

public class CertificateVerify extends Handshake.Body {

	byte[] sign;
    public CertificateVerify(IKeyManager keyManager, List<Handshake> handshakes) throws IOException {
    	ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Handshake handshake : handshakes) {
            out.write(handshake.getBytes());
        }
        // SM3(handshake_mesages)
        byte[] hash = Crypto.hash(out.toByteArray());
        byte[] sign = keyManager.doSign(hash, 0, hash.length);
        byte[] byArray3 = new byte[32];
        byte[] byArray4 = new byte[32];
        System.arraycopy(sign, 0, byArray3, 0, 32);
        System.arraycopy(sign, 32, byArray4, 0, 32);
        BigInteger[] bigIntegerArray = new BigInteger[]{new BigInteger(1, byArray3), new BigInteger(1, byArray4)};
        ASN1Encodable[] aSN1EncodableArray = new ASN1Integer[]{new ASN1Integer(bigIntegerArray[0]), new ASN1Integer(bigIntegerArray[1])};
        sign = new DERSequence(aSN1EncodableArray).getEncoded("DER");
    	this.sign = sign;
	}
	public static Body read(InputStream input) {
        return null;
    }

	@Override
	public byte[] getBytes() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int pl = sign.length;
		out.write(pl >>> 8 & 0xFF);
		out.write(pl & 0xFF);
		out.write(sign);
		return out.toByteArray();
	}

}
