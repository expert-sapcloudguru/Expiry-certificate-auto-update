import com.sap.gateway.ip.core.customdev.util.Message;

import java.util.HashMap;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.text.SimpleDateFormat;

import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.net.ssl.*;

import com.sap.it.api.ITApiFactory
import com.sap.it.api.mapping.ValueMappingApi

def Message processData(Message message) {
    def map = message.getHeaders();
    def mapProp = message.getProperties();
    
    String Alias = map.get("Alias")
    
    String getCertExpirydate = map.get("CertExpiryDate");

    Date CertExpirydate = new SimpleDateFormat("yyyy-MM-dd").parse(getCertExpirydate);

    Date dateNow = new Date(System.currentTimeMillis());

    long dateDiff = CertExpirydate.getTime() - dateNow.getTime();

    def daysToExpire = TimeUnit.DAYS.convert(dateDiff, TimeUnit.MILLISECONDS);

    def valueMapApi = ITApiFactory.getApi(ValueMappingApi.class, null)
    def value = valueMapApi.getMappedValue('source', 'alias', Alias, 'target', 'url')
    
    def encodedCert = ""
    
    if(value != null && value != ""){
    
        //---Get Certificate---
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket)factory.createSocket(value, 443);
        
        SSLSession session = socket.getSession();
        X509Certificate cert;
    
        try{
            cert = (X509Certificate) session.getPeerCertificates()[0];
        }catch (SSLPeerUnverifiedException e) {
            daysToExpire = -2
        }
    
        encodedCert = 
    		"-----BEGIN CERTIFICATE-----\n" + 
    		Base64.getMimeEncoder().encodeToString(cert.getEncoded()) +
    		"\n-----END CERTIFICATE-----";
        //---END Get Certificate---
    
        message.setProperty("Hexalias", String.format("%x", new BigInteger(1, Alias.getBytes("UTF-8"))))
    }
    message.setProperty("encodedCert", encodedCert);

    message.setHeader("daysToExpire", daysToExpire);

   return message;
}