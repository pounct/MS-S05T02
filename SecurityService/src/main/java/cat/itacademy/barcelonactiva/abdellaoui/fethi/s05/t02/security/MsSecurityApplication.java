package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Config.RsaKeysConfiguration;

@EnableConfigurationProperties(RsaKeysConfiguration.class)
@EnableGlobalMethodSecurity(prePostEnabled = true)
@SpringBootApplication
public class MsSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(MsSecurityApplication.class, args);
	}
	// para reglar noop del password usamos passwordEncoder 
    // i lo injectamos  en nustra classe de configuration
    
    @Bean
    PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
