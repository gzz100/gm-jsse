package com.aliyun.gmsse;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

public class SessionContext implements SSLSessionContext {
	
	private Map<String,SessionKey> cache = new HashMap<String,SessionKey>();
	
	private ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();

	public SessionKey getSessionKey(String address) {
		rwl.readLock().lock();
		try {
			return cache.get(address);
		}finally{
			rwl.readLock().unlock();
		}
	}

	public void setSessionKey(String address, SessionKey newSessionKey) {
		rwl.writeLock().lock();
		try {
			cache.put(address, newSessionKey);
		}finally{
			rwl.writeLock().unlock();
		}
	}
	
    public SessionContext() {

    }

    public Enumeration<byte[]> getIds() {
        // TODO Auto-generated method stub
        return null;
    }

    public SSLSession getSession(byte[] arg0) {
        // TODO Auto-generated method stub
        return null;
    }

    public int getSessionCacheSize() {
        // TODO Auto-generated method stub
        return 0;
    }

    public int getSessionTimeout() {
        // TODO Auto-generated method stub
        return 0;
    }

    public void setSessionCacheSize(int arg0) throws IllegalArgumentException {
        // TODO Auto-generated method stub

    }

    public void setSessionTimeout(int arg0) throws IllegalArgumentException {
        // TODO Auto-generated method stub

    }
    
}
