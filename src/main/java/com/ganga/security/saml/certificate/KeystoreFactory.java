package com.ganga.security.saml.certificate;

import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class KeystoreFactory {
	
	private ResourceLoader resourceLoader;

    public KeystoreFactory() {
        resourceLoader = new DefaultResourceLoader();
    }

    public KeystoreFactory(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public KeyStore loadKeystore(String certResourceLocation, String privateKeyResourceLocation, String alias, String keyPassword) {
        KeyStore keystore = createEmptyKeystore();
        X509Certificate cert = loadCert(certResourceLocation);
        RSAPrivateKey privateKey = loadPrivateKey(privateKeyResourceLocation);
        addKeyToKeystore(keystore, cert, privateKey, alias, keyPassword);
        return keystore;
    }

    public void addKeyToKeystore(KeyStore keyStore, X509Certificate cert, RSAPrivateKey privateKey, String alias, String password) {
        KeyStore.PasswordProtection pass = new KeyStore.PasswordProtection(password.toCharArray());
        Certificate[] certificateChain = {cert};
        try {
			keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(privateKey, certificateChain), pass);
		} catch (KeyStoreException e) {
			throw new RuntimeException(e.getMessage());
		}
    }

    public KeyStore createEmptyKeystore() {
        KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("JKS");
		} catch (KeyStoreException e) {
			throw new RuntimeException(e.getMessage());
		}
        try {
			keyStore.load(null, "".toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new RuntimeException(e.getMessage());
		}
        return keyStore;
    }

    
    public X509Certificate loadCert(String certLocation) {
        CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X509");
		} catch (CertificateException e) {
			throw new RuntimeException(e.getMessage());
		}
        Resource certRes = resourceLoader.getResource(certLocation);
        X509Certificate cert;
		try {
			cert = (X509Certificate) cf.generateCertificate(certRes.getInputStream());
		} catch (CertificateException | IOException e) {
			throw new RuntimeException(e.getMessage());
		}
        return cert;
    }

    
    public RSAPrivateKey loadPrivateKey(String privateKeyLocation) {
        Resource keyRes = resourceLoader.getResource(privateKeyLocation);
        byte[] keyBytes;
		try {
			keyBytes = StreamUtils.copyToByteArray(keyRes.getInputStream());
		} catch (IOException e) {
			throw new RuntimeException(e.getMessage());
		}
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
        RSAPrivateKey privateKey;
		try {
			privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e.getMessage());
		}
        return privateKey;
    }

    public void setResourceLoader(DefaultResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

}
