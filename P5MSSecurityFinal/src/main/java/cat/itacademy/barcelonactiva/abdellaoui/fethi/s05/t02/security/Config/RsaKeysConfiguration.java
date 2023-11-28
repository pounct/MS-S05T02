package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Config;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "rsa") 
public record RsaKeysConfiguration(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
}
