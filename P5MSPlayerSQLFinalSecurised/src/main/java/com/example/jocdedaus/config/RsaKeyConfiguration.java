package com.example.jocdedaus.config;

import java.security.interfaces.RSAPublicKey;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "rsa") 
public record RsaKeyConfiguration(RSAPublicKey publicKey) {
}
