package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Config;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.boot.context.properties.ConfigurationProperties;

//va a ver en proprieties y recuperar keys con prefix rsa
@ConfigurationProperties(prefix = "rsa") 
public record RsaKeysConfiguration(RSAPublicKey publicKey, RSAPrivateKey privateKey) {

}

// a hora podemos usar lo en la classe de configuracio (injection)
