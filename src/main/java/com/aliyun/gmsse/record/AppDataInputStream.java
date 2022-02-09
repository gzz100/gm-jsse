package com.aliyun.gmsse.record;

import java.io.IOException;
import java.io.InputStream;

import com.aliyun.gmsse.Record;
import com.aliyun.gmsse.RecordStream;

public class AppDataInputStream extends InputStream {

    private RecordStream recordStream;
    private Record lastRecord;
    private int lastRecordAvailableLength = 0;

    public AppDataInputStream(RecordStream recordStream) {
        this.recordStream = recordStream;
    }

    @Override
    public int read() throws IOException {
        byte[] buf = new byte[1];
        int ret = read(buf, 0, 1);
        return ret < 0 ? -1 : buf[0] & 0xFF;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
    	if(lastRecordAvailableLength <= 0)
    	{
    		lastRecord = recordStream.read(true);
    		lastRecordAvailableLength = lastRecord.fragment.length;
    	}
        int length = Math.min(lastRecordAvailableLength, len);
        System.arraycopy(lastRecord.fragment, lastRecord.fragment.length - lastRecordAvailableLength, b, off, length);
        lastRecordAvailableLength -= length;
        return length;
    }
}
