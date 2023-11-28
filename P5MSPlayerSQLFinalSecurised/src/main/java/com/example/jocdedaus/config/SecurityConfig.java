package com.example.jocdedaus.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@AllArgsConstructor
//@Slf4j
public class SecurityConfig {

	private RsaKeyConfiguration keyConfiguration;
		
	


    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		
		return httpSecurity
				.csrf(csrf -> csrf.disable())
				.sessionManagement(ses -> ses.sessionCreationPolicy(SessionCreationPolicy.STATELESS))				

				.authorizeHttpRequests(auth -> auth
						.requestMatchers(new AntPathRequestMatcher("/swagger-ui/**"))
						.permitAll())	
				.authorizeHttpRequests(aut -> aut.anyRequest().authenticated())
				.oauth2ResourceServer(oa-> oa.jwt(Customizer.withDefaults()))				
				.build();
	}

	@Bean
	JwtDecoder jwtDecoder() {
		return NimbusJwtDecoder.withPublicKey(keyConfiguration.publicKey()).build();
	}


}
