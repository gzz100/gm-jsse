package com.aliyun.gmsse;

import com.aliyun.gmsse.Record.ContentType;
import com.aliyun.gmsse.crypto.Crypto;
import com.aliyun.gmsse.handshake.Certificate;
import com.aliyun.gmsse.handshake.CertificateVerify;
import com.aliyun.gmsse.handshake.ClientHello;
import com.aliyun.gmsse.handshake.ClientKeyExchange;
import com.aliyun.gmsse.handshake.Finished;
import com.aliyun.gmsse.handshake.ServerHello;
import com.aliyun.gmsse.handshake.ServerKeyExchange;
import com.aliyun.gmsse.record.Alert;
import com.aliyun.gmsse.record.AppDataInputStream;
import com.aliyun.gmsse.record.AppDataOutputStream;
import com.aliyun.gmsse.record.ChangeCipherSpec;
import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Type;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * GMSSLSocket
 */
public class GMSSLSocket extends SSLSocket {
    static List<CipherSuite> supportedSuites = new ArrayList<CipherSuite>();
    static List<ProtocolVersion> supportedPtrotocols = new ArrayList<ProtocolVersion>();

    static {
        // setup suites
        supportedSuites.add(CipherSuite.NTLS_SM2_WITH_SM4_SM3);
        supportedSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);

        // setup protocols
        supportedPtrotocols.add(ProtocolVersion.NTLS_1_1);
        supportedPtrotocols.add(ProtocolVersion.TLS_3_3);
    }

    GMSSLSession session;
    BufferedOutputStream handshakeOut;
    int port;
    private boolean createSessions;
    public SSLSessionContext sessionContext;
    private String remoteHost;
    private boolean clientMode;
    private Socket underlyingSocket;
    private boolean autoClose;
    // raw socket in/out
    private InputStream socketIn;
    private OutputStream socketOut;
    private RecordStream recordStream;

    private SecurityParameters securityParameters = new SecurityParameters();
    List<Handshake> handshakes = new ArrayList<Handshake>();

    public GMSSLSocket(String host, int port) throws IOException {
        super(host, port);
        remoteHost = host;
        this.port = port;
        initialize();
    }

    private void initialize() {
        session = new GMSSLSession(supportedSuites, supportedPtrotocols);
    }
    
    public GMSSLSocket() {
    	super();
    	initialize();
    }

    public GMSSLSocket(InetAddress host, int port) throws IOException {
        super(host, port);
        remoteHost = host.getHostName();
        this.port = port;
        if (remoteHost == null) {
            remoteHost = host.getHostAddress();
        }
        initialize();
    }

    public GMSSLSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        underlyingSocket = socket;
        remoteHost = host;
        this.port = port;
        this.autoClose = autoClose;
        initialize();
    }
    
    @Override
	public void connect(SocketAddress endpoint, int timeout) throws IOException {
    	remoteHost = ((InetSocketAddress)endpoint).getHostName();
        this.port = ((InetSocketAddress)endpoint).getPort();
		super.connect(endpoint, timeout);
	}


    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public boolean getEnableSessionCreation() {
        return createSessions;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        List<String> suites = new ArrayList<String>();
        for (CipherSuite suite : session.enabledSuites) {
            suites.add(suite.getName());
        }
        return suites.toArray(new String[0]);
    }

    @Override
    public String[] getEnabledProtocols() {
        List<String> protocols = new ArrayList<String>();
        for (ProtocolVersion version : session.enabledProtocols) {
            protocols.add(version.toString());
        }
        return protocols.toArray(new String[0]);
    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public SSLSession getSession() {
        return session;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        List<String> suites = new ArrayList<String>();
        for (CipherSuite suite : supportedSuites) {
            suites.add(suite.getName());
        }
        return suites.toArray(new String[0]);
    }

    @Override
    public String[] getSupportedProtocols() {
        List<String> protocols = new ArrayList<String>();
        for (ProtocolVersion version : supportedPtrotocols) {
            protocols.add(version.toString());
        }
        return protocols.toArray(new String[0]);
    }

    @Override
    public boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        createSessions = flag;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        if (suites == null || suites.length == 0) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < suites.length; i++) {
            if (CipherSuite.forName(suites[i]) == null) {
                throw new IllegalArgumentException("unsupported suite: " + suites[i]);
            }
        }

        synchronized (session.enabledSuites) {
            session.enabledSuites.clear();
            for (int i = 0; i < suites.length; i++) {
                CipherSuite suite = CipherSuite.forName(suites[i]);
                if (!session.enabledSuites.contains(suite)) {
                    session.enabledSuites.add(suite);
                }
            }
        }
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        if (protocols == null || protocols.length == 0) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < protocols.length; i++) {
            if (!(protocols[i].equalsIgnoreCase("NTLSv1.1"))) {
                throw new IllegalArgumentException("unsupported protocol: " + protocols[i]);
            }
        }

        synchronized (session.enabledProtocols) {
            session.enabledProtocols.clear();
            for (int i = 0; i < protocols.length; i++) {
                session.enabledProtocols.add(ProtocolVersion.NTLS_1_1);
            }
        }
    }

    @Override
    public void setNeedClientAuth(boolean need) {
    }

    @Override
    public void setUseClientMode(boolean mode) {
        clientMode = mode;
    }

    @Override
    public void setWantClientAuth(boolean want) {
    }

    @Override
    public void startHandshake() throws IOException {
    	

        session.protocol = ProtocolVersion.NTLS_1_1;
        if(Crypto.CryptoType == 1)
        {
        	session.protocol = ProtocolVersion.TLS_3_3;
        }
        
        ensureConnect();

    	byte[] sessionId = null;
    	SessionKey key = session.sessionContext.getSessionKey(getRemoteSocketAddress().toString());
    	if(key != null)
    		sessionId = key.lastSessionID.getId();
    	else
        	sessionId = new byte[0];
        // send ClientHello
        sendClientHello(sessionId);

        // recive ServerHello
        ByteArrayInputStream _input = receiveServerHello();

        if(key == null || !key.lastSessionID.same(session.sessionId))
        {
        	System.out.println("===>new TLS Session");
	        // recive ServerCertificate
        	_input = receiveServerCertificate(_input);
	
	        // recive receiveServerHelloDone
        	receiveServerHelloDone(_input);
	
	        
	        if(session.certificateRequest)
	        {
	        	sendClientCertificate();
	        }
	
	        // send ClientKeyExchange
	        sendClientKeyExchange();
	
	        if(session.certificateRequest)
	        {
	        	sendCertificateVerify();
	        }
	        
	        GenerateKeyBlock();
	        
	        // send ChangeCipherSpec
	        sendChangeCipherSpec();

	        // send Finished
	        sendFinished();

	        // recive ChangeCipherSpec
	        receiveChangeCipherSpec();

	        // recive finished
	        receiveFinished();
        }else {
        	securityParameters.masterSecret = key.lastMasterKey;
        	
        	GenerateKeyBlock();
            
            // recive ChangeCipherSpec
            receiveChangeCipherSpec();

            // recive finished
            receiveFinished();
            
            // send ChangeCipherSpec
            sendChangeCipherSpec();

            // send Finished
            sendFinished();
        }
    }

    private void receiveFinished() throws IOException {
        Record rc = recordStream.read(true);
        Handshake hs = Handshake.read(new ByteArrayInputStream(rc.fragment));
        Finished finished = (Finished) hs.body;
        Finished serverFinished = new Finished(securityParameters.masterSecret, "server finished", handshakes);
        if (!Arrays.equals(finished.getBytes(), serverFinished.getBytes())) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.HANDSHAKE_FAILURE);
            throw new AlertException(alert, true);
        }
        handshakes.add(hs);
    }

    private void receiveChangeCipherSpec() throws IOException {
        Record rc = recordStream.read();
        ChangeCipherSpec ccs = ChangeCipherSpec.read(new ByteArrayInputStream(rc.fragment));
    }

    private void sendFinished() throws IOException {
        Finished finished = new Finished(securityParameters.masterSecret, "client finished", handshakes);
        Handshake hs = new Handshake(Handshake.Type.FINISHED, finished);
        Record rc = new Record(ContentType.HANDSHAKE, session.protocol, hs.getBytes());
        recordStream.write(rc, true);
        handshakes.add(hs);
    }

    private void sendChangeCipherSpec() throws IOException {
        Record rc = new Record(ContentType.CHANGE_CIPHER_SPEC, session.protocol, new ChangeCipherSpec().getBytes());
        recordStream.write(rc);
    }
    
    private void sendClientCertificate() throws IOException {
        X509Certificate[] _cert = null;
        try {
	        _cert = ((IKeyManager)session.keyManager).getCert();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        Certificate ckex = new Certificate(_cert) ;
        Handshake hs = new Handshake(Handshake.Type.CERTIFICATE, ckex);
        Record rc = new Record(ContentType.HANDSHAKE, session.protocol, hs.getBytes());
        recordStream.write(rc);
        handshakes.add(hs);
    }
    
    private void sendCertificateVerify() throws IOException {
        CertificateVerify cv = new CertificateVerify((IKeyManager)session.keyManager,handshakes);
        Handshake hs = new Handshake(Handshake.Type.CERTIFICATE_VERIFY, cv);
        Record rc = new Record(ContentType.HANDSHAKE, session.protocol, hs.getBytes());
        recordStream.write(rc);
        handshakes.add(hs);
    }
    
    private void GenerateKeyBlock() throws IOException
    {
    	// key_block = PRF(SecurityParameters.master_secret锛�"keyexpansion"锛�
        // SecurityParameters.server_random +SecurityParameters.client_random);
        // new TLSKeyMaterialSpec(masterSecret, TLSKeyMaterialSpec.KEY_EXPANSION,
        // key_block.length, server_random, client_random))
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(securityParameters.serverRandom);
        os.write(securityParameters.clientRandom);
        byte[] seed = os.toByteArray();
        byte[] keyBlock = null;
        try {
        	keyBlock = Crypto.prf(securityParameters.masterSecret, "key expansion".getBytes(), seed, 128);
        } catch (Exception e) {
            throw new SSLException("caculate key block failed", e);
        }

        // client_write_MAC_secret[SecurityParameters.hash_size]
        // server_write_MAC_secret[SecurityParameters.hash_size]
        // client_write_key[SecurityParameters.key_material_length]
        // server_write_key[SecurityParameters.key_material_length]
        // clientWriteIV
        // serverWriteIV

        // client mac key
        byte[] clientMacKey = new byte[32];
        System.arraycopy(keyBlock, 0, clientMacKey, 0, 32);
        recordStream.setClientMacKey(clientMacKey);

        // server mac key
        byte[] serverMacKey = new byte[32];
        System.arraycopy(keyBlock, 32, serverMacKey, 0, 32);
        recordStream.setServerMacKey(serverMacKey);

        // client write key
        byte[] clientWriteKey = new byte[16];
        System.arraycopy(keyBlock, 64, clientWriteKey, 0, 16);
        if(Crypto.CryptoType == 0)
        {
        	SM4Engine writeCipher = new SM4Engine();
            writeCipher.init(true, new KeyParameter(clientWriteKey));
            recordStream.setWriteCipher(writeCipher);
        } else {
        	AESEngine writeCipher = new AESEngine();
            writeCipher.init(true, new KeyParameter(clientWriteKey));
            recordStream.setWriteCipher(writeCipher);
        }
        

        // server write key
        byte[] serverWriteKey = new byte[16];
        System.arraycopy(keyBlock, 80, serverWriteKey, 0, 16);
        if(Crypto.CryptoType == 0)
        {
	        SM4Engine readCipher = new SM4Engine();
	        readCipher.init(false, new KeyParameter(serverWriteKey));
	        recordStream.setReadCipher(readCipher);
        } else {
        	AESEngine readCipher = new AESEngine();
	        readCipher.init(false, new KeyParameter(serverWriteKey));
	        recordStream.setReadCipher(readCipher);
        }

        // client write iv
        byte[] clientWriteIV = new byte[16];
        System.arraycopy(keyBlock, 96, clientWriteIV, 0, 16);
        recordStream.setClientWriteIV(clientWriteIV);

        // server write iv
        byte[] serverWriteIV = new byte[16];
        System.arraycopy(keyBlock, 112, serverWriteIV, 0, 16);
        recordStream.setServerWriteIV(serverWriteIV);
    }

    private void sendClientKeyExchange() throws IOException {
        ClientKeyExchange ckex = new ClientKeyExchange(session.protocol, session.random, securityParameters.encryptionCert);

        Handshake hs = new Handshake(Handshake.Type.CLIENT_KEY_EXCHANGE, ckex);
        Record rc = new Record(ContentType.HANDSHAKE, session.protocol, hs.getBytes());
        recordStream.write(rc);
        handshakes.add(hs);
        
        try {
            securityParameters.masterSecret = ckex.getMasterSecret(securityParameters.clientRandom,
                    securityParameters.serverRandom);
        } catch (Exception e) {
            e.printStackTrace();
            throw new SSLException("caculate master secret failed", e);
        }
        String remoteHost = this.getRemoteSocketAddress().toString();
        SessionKey key = new SessionKey();
    	key.lastSessionID = session.sessionId;
    	key.lastMasterKey = securityParameters.masterSecret;
    	session.sessionContext.setSessionKey(remoteHost, key);
    }

    private void receiveServerHelloDone(ByteArrayInputStream _input) throws IOException {
    	if(_input.available() == 0)
    	{
            Record rc = recordStream.read();
            _input = new ByteArrayInputStream(rc.fragment);
    	}
        Handshake shdf = Handshake.read(_input);
        if(shdf.type == Type.SERVER_KEY_EXCHANGE)
        {
        	ServerKeyExchange ske = (ServerKeyExchange) shdf.body;
            // signature cert
            X509Certificate signCert = session.peerCerts[0];
            // encryption cert
            X509Certificate encryptionCert = session.peerCerts[1];
            // verify the signature
            boolean verified = false;

            try {
                verified = ske.verify(signCert.getPublicKey(), securityParameters.clientRandom,
                        securityParameters.serverRandom, encryptionCert);
            } catch (Exception e2) {
                throw new SSLException("server key exchange verify fails!", e2);
            }

            if (!verified) {
                throw new SSLException("server key exchange verify fails!");
            }

            handshakes.add(shdf);
        	if(_input.available() == 0)
        	{
        		Record rc = recordStream.read();
        		_input = new ByteArrayInputStream(rc.fragment);
        	}

            shdf = Handshake.read(_input);
        }
        if(shdf.type == Type.CERTIFICATE_REQUEST)
        {
        	session.certificateRequest = true;
        	handshakes.add(shdf);
        	
        	if(_input.available() == 0)
        	{
        		Record rc = recordStream.read();
        		_input = new ByteArrayInputStream(rc.fragment);
        	}

            shdf = Handshake.read(_input);
        }
        handshakes.add(shdf);
    }

    private ByteArrayInputStream receiveServerCertificate(ByteArrayInputStream _input) throws IOException {
    	if(_input.available() == 0)
    	{
    		Record rc = recordStream.read();
    		_input = new ByteArrayInputStream(rc.fragment);
    	}
        Handshake cf = Handshake.read(_input);
        Certificate cert = (Certificate) cf.body;
        X509Certificate[] peerCerts = cert.getCertificates();
        try {
            session.trustManager.checkServerTrusted(peerCerts, session.cipherSuite.getAuthType());
        } catch (CertificateException e) {
            throw new SSLException("could not verify peer certificate!", e);
        }
        session.peerCerts = peerCerts;
        session.peerVerified = true;
        handshakes.add(cf);

        if(Crypto.CryptoType == 0)
        	securityParameters.encryptionCert = session.peerCerts[1];
        else
        	securityParameters.encryptionCert = session.peerCerts[0];
        return _input;
    }

    private ByteArrayInputStream receiveServerHello() throws IOException {
        Record rc = recordStream.read();
        if (rc.contentType != Record.ContentType.HANDSHAKE) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.UNEXPECTED_MESSAGE);
            throw new AlertException(alert, true);
        }
        ByteArrayInputStream _input = new ByteArrayInputStream(rc.fragment);
        Handshake hsf = Handshake.read(_input);
        ServerHello sh = (ServerHello) hsf.body;
        sh.getCompressionMethod();
        // TODO: process the compresion method
        session.cipherSuite = sh.getCipherSuite();
        session.peerHost = remoteHost;
        session.peerPort = port;
        session.sessionId = new GMSSLSession.ID(sh.getSessionId());
        handshakes.add(hsf);
        securityParameters.serverRandom = sh.getRandom();
        return _input;
    }

    private void sendClientHello(byte[] sessionId) throws IOException {
        int gmtUnixTime = (int) (System.currentTimeMillis() / 1000L);
        ClientRandom random = new ClientRandom(gmtUnixTime, session.random.generateSeed(28));
        List<CipherSuite> suites = session.enabledSuites;
        List<CompressionMethod> compressions = new ArrayList<CompressionMethod>(2);
        compressions.add(CompressionMethod.NULL);
        ClientHello ch = new ClientHello(session.protocol, random, sessionId, suites, compressions);
        Handshake hs = new Handshake(Handshake.Type.CLIENT_HELLO, ch);
        Record rc = new Record(Record.ContentType.HANDSHAKE, session.protocol, hs.getBytes());
        recordStream.write(rc);
        handshakes.add(hs);
        securityParameters.clientRandom = random.getBytes();
    }

    private void ensureConnect() throws IOException {
        if (underlyingSocket != null) {
            if (!underlyingSocket.isConnected()) {
                underlyingSocket.connect(this.getRemoteSocketAddress());
            }
        } else {
            if (!this.isConnected()) {
                SocketAddress socketAddress = new InetSocketAddress(remoteHost, port);
                connect(socketAddress);
            }
        }
        if (underlyingSocket != null) {
            socketIn = underlyingSocket.getInputStream();
            socketOut = underlyingSocket.getOutputStream();
        } else {
            socketIn = super.getInputStream();
            socketOut = super.getOutputStream();
        }
        recordStream = new RecordStream(socketIn, socketOut);
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return new AppDataOutputStream(recordStream);
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new AppDataInputStream(recordStream);
    }
}
