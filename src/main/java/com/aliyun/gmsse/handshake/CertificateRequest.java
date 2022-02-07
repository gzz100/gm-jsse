package com.aliyun.gmsse.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;


public class CertificateRequest extends Handshake.Body {

	int certCount = 0;
	int[] certTypes;
	byte[][] distinguishedNames;
	
	public CertificateRequest(int certCount, int[] certTypes, byte[][] distinguishedNames)
	{
		this.certCount = certCount;
		this.certTypes = certTypes;
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
    	for(int i=0;i<distinguishedNames.length;i++)
    	{
    		if(distinguishedNames[i] != null)
    		{
    			alen+=distinguishedNames[i].length;
    	    	 alen+=2;
    		}
    	 
    	}
    	bytes.write(alen >> 8 & 0xFF);
		bytes.write(alen & 0xFF);
    	for(int i=0;i<distinguishedNames.length;i++)
    	{
    		if(distinguishedNames[i] != null)
    		{
	    		int len = distinguishedNames[i].length;
	    		bytes.write(len >> 8 & 0xFF);
	    		bytes.write(len & 0xFF);
	    		bytes.write(distinguishedNames[i]);
    		}
    	}
        return bytes.toByteArray();
    }

    public static Body read(InputStream input) throws IOException {
    	int count = input.read() & 0xFF;
    	int[] types = new int[count];
    	byte[][] names = new byte[count][];
    	for(int i=0;i<count;i++)
    	{
    		types[i] = input.read() & 0xFF;
    	}
    	int len = (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
    	if(len>0)
    	{
    		for(int i=0;i<count;i++)
        	{
        		len = (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
        		names[i] = new byte[len];
        		input.read(names[i]);
        	}
    	}
    	
        return new CertificateRequest(count,types,names);
    }

}
