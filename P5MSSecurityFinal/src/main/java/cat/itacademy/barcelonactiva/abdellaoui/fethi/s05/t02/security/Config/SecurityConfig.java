package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.services.UserDetailsServiceImpl;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Config.SecurityConfig;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
//@Slf4j
public class SecurityConfig {

	private RsaKeysConfiguration keysConfiguration;
		
	
	@Bean
	AuthenticationManager authenticationManager(UserDetailsServiceImpl userDetailsService) {
		
		var daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
		return new ProviderManager(daoAuthenticationProvider);		
	}
	
	@Bean
	MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
	    return new MvcRequestMatcher.Builder(introspector);
	}

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, MvcRequestMatcher.Builder mvc) throws Exception {
		
		return httpSecurity
				.csrf(csrf -> csrf.disable())
				.sessionManagement(ses -> ses.sessionCreationPolicy(SessionCreationPolicy.STATELESS))				
//				.headers(head -> head.frameOptions(fo -> fo.disable()))
				.authorizeHttpRequests(auth -> auth
						.requestMatchers(new AntPathRequestMatcher("/test/RestApi/**"))
						.permitAll())			
				.authorizeHttpRequests(auth -> auth
						.requestMatchers(new AntPathRequestMatcher("/users/**"))
						.permitAll())
				.authorizeHttpRequests(aut->aut
						.requestMatchers(new AntPathRequestMatcher("/auth/token/**"))
						.permitAll())
				.authorizeHttpRequests(aut->aut
						.requestMatchers(new AntPathRequestMatcher("/register/**"))
						.permitAll())
				.authorizeHttpRequests(aut->aut
						.requestMatchers(new AntPathRequestMatcher("/login/**"))
						.permitAll())
				.authorizeHttpRequests(aut -> aut.anyRequest().authenticated())
				//.httpBasic(Customizer.withDefaults())
				.oauth2ResourceServer(oa-> oa.jwt(Customizer.withDefaults()))				
				.build();
	}

	@Bean
	JwtDecoder jwtDecoder() {
		return NimbusJwtDecoder.withPublicKey(keysConfiguration.publicKey()).build();
	}

	@Bean
	JwtEncoder jwtEncoder() {
		JWK jwk = new RSAKey.Builder(keysConfiguration.publicKey()).privateKey(keysConfiguration.privateKey()).build();
		JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwkSource);
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
