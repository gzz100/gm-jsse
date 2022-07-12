package com.aliyun.gmsse.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import com.aliyun.gmsse.crypto.Crypto;
import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;


public class CertificateRequest extends Handshake.Body {

	int certCount = 0;
	int[] certTypes;
	int[] sha;
	List<byte[]> distinguishedNames;
	
	public CertificateRequest(int certCount, int[] certTypes, int[] shas, List<byte[]> distinguishedNames)
	{
		this.certCount = certCount;
		this.certTypes = certTypes;
		this.sha = shas;
		this.distinguishedNames = distinguishedNames;
	}
    @Override
    public byte[] getBytes() throws IOException {
    	ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    	bytes.write(certCount);
    	for(int i=0;i<certTypes.length;i++)
    	{
    		bytes.write(certTypes[i]);
    	}
    	int alen = 0;
    	if(sha != null)
    	{
    		alen = sha.length * 2;
    		bytes.write(alen >> 8 & 0xFF);
    		bytes.write(alen & 0xFF);
    		for(int i=0;i<sha.length;i++)
        	{
    			bytes.write(sha[i] >> 8 & 0xFF);
        		bytes.write(sha[i] & 0xFF);
        	}
    	}
    	
    	
    	alen = 0;
    	for(int i=0;i<distinguishedNames.size();i++)
    	{
    		if(distinguishedNames.get(i) != null)
    		{
    			alen+=distinguishedNames.get(i).length;
    	    	 alen+=2;
    		}
    	 
    	}
    	bytes.write(alen >> 8 & 0xFF);
		bytes.write(alen & 0xFF);
    	for(int i=0;i<distinguishedNames.size();i++)
    	{
    		if(distinguishedNames.get(i) != null)
    		{
	    		int len = distinguishedNames.get(i).length;
	    		bytes.write(len >> 8 & 0xFF);
	    		bytes.write(len & 0xFF);
	    		bytes.write(distinguishedNames.get(i));
    		}
    	}
        return bytes.toByteArray();
    }

    public static Body read(InputStream input) throws IOException {
    	int count = input.read() & 0xFF;
    	int[] shas = null;
    	int[] types = new int[count];
    	List<byte[]> names = new ArrayList<byte[]>();
    	for(int i=0;i<count;i++)
    	{
    		types[i] = input.read() & 0xFF;
    	}
    	if(Crypto.CryptoType == 1) //RSA TLS1.2
    	{
    		int len = (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
    		shas = new int[len/2];
    		for(int i=0;i<shas.length;i++)
    		{
    			int sha = (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
    			shas[i] = sha;
    		}
    	}
    	int len = (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
    	while(len>0)
    	{
        		int dlen = (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
        		byte[] dname = new byte[dlen];
        		input.read(dname);
        		names.add(dname);
        		len-=(dlen+2);
    	}
    	
        return new CertificateRequest(count,types,shas,names);
    }

}
