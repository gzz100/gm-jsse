package com.aliyun.gmsse;

import com.aliyun.gmsse.record.Alert;

import javax.net.ssl.SSLException;

public class AlertException extends SSLException {
    /**
     *
     */
    private static final long serialVersionUID = -2141851102337515375L;


    AlertException(Alert alert, boolean isLocal) {
        super(alert.getDescription().toString());
    }
}
