package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


	// personalitzar la configuracio
	// afegir notacio @ Configuration
	// enable ña segutitat

	// generalment, heretarem d'una classe de seguretat web configurable adapter
	// redefinar metodes...
	// hi ha una manera molt millor d'utilitzar Beans

	// Basic Authentication consiste a enviar un userName y un password
	// hay que crear usarios y sus passwords
	// usamos en primer in Memory authentication

	// Para no usar password encoder en password("1234")
	// usamos noop opcio para no password encoder
	///////////////////////////////

	// afegir .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
	// para usar jwt en spring security
	// tenemos que crear por eso 2 objetos jwtEncoder y jwtDecoder
	// son dos Beans a crear
	// Y para crearlos debemos firmar los tokens usando RSA
	// necisitamos dos llaves publica y privada publicKey y privateKey

	// creamos un reportorio certs en resources
	// guardamos la privada en servicio de Authentication y compartir la public por
	// los servicios para firmar el token
	// podemos usar openssl
	// o con java con la classe GenerateKayPair

	// afegir a proprities rsa.public-key =
	// rsa.public-key=classpath:certs/public.pem
	// rsa.private-key=classpath:certs/private.pem
	// y crear una classe de configuration que nos permite leer esos datos(keys)
	// en config package creamos este classe o record RsaKeysConfiguration()

	// inyectar los keys recuperadas con el record
	private RsaKeysConfiguration keysConfiguration;
	// injeccio passwordEncoder
	private PasswordEncoder passwordEncoder;
		

	// injeccio amb constructor
	public SecurityConfig(RsaKeysConfiguration keysConfiguration, PasswordEncoder passwordEncoder) {
		this.keysConfiguration = keysConfiguration;
		this.passwordEncoder = passwordEncoder;
	}

	
	// creamos AuthenticationManager y para configurar injectamos AuthenticationConfiguration
	// este tecmica mo es recomendada
	//@Bean
//	AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration ) throws Exception {
//		return authenticationConfiguration.getAuthenticationManager();		
//	}
	// usamos este tecnica mejor
	// lo usamos en el controller cuando authentification
	@Bean
	AuthenticationManager authenticationManager(UserDetailsService userDetailsService) {
		// remplacer DaoAuthenticationProvider por var
		var daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
		return new ProviderManager(daoAuthenticationProvider);		
	}
	
	// para AuthenticationManager  cambiamos el typo de inMemoryUserDetailsManager a
	// el inteface UserDetailsService
	@Bean
	UserDetailsService inMemoryUserDetailsManager() {
		return new InMemoryUserDetailsManager(
				User.withUsername("user1").password(passwordEncoder.encode("1234")).authorities("USER").build(),
				User.withUsername("user2").password(passwordEncoder.encode("1234")).authorities("USER").build(),
				User.withUsername("admin").password(passwordEncoder.encode("1234")).authorities("ADMIN", "USER").build()

		);

	}
	
	@Bean
	MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
	    return new MvcRequestMatcher.Builder(introspector);
	}

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, MvcRequestMatcher.Builder mvc) throws Exception {
		return httpSecurity
				.csrf(csrf -> csrf.disable())
				.authorizeRequests(aut->aut.requestMatchers(mvc.pattern("/api/token/**")).permitAll())
				.authorizeRequests(aut -> aut.anyRequest().authenticated())
				.sessionManagement(ses -> ses.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
				.httpBasic(Customizer.withDefaults())
				.build();
	}

	// ya como tenemos nos keysConfiguration podemos crear jwtEncoder y jwtDecoder
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

	// y crear en el controllers el endPoint "api/token/" en la classe
	// SeguretatController
}
