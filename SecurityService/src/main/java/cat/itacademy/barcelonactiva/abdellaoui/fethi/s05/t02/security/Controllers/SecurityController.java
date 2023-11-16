package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Controllers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class SecurityController {
	
	private JwtEncoder jwtEncoder;
	private JwtDecoder jwtDecoder;
	private AuthenticationManager authenticationManager;
	// para get authoreties
	private UserDetailsService userDetailsService;
	// en authent. Basic spring lo hace automaticamente
	// y con AuthenticationManager lo hacemos nosotros
	// es decir recuperar user y el pass y hacemos la authentif.


	// para injectar jwtEncoder amb constructor
	// o con AllArg constructor
	public SecurityController(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder,
			AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
		this.jwtEncoder = jwtEncoder;
		this.jwtDecoder = jwtDecoder;
		this.authenticationManager = authenticationManager;
		this.userDetailsService = userDetailsService;
	}
	// y crear un metode retorna un token
	// authentication ya como uasamos basicAuthentication
	// authentication lo inyectemos para recupera username (subject) y password
	// @PostMapping("/token")
	// public Map<String, String> jwtToken(Authentication authentication){
	// a hora remplasamos Authentication para username y password

	// afegir ambRefreshToken bool para refresh el token si true 5mn sino 30 mn
	@PostMapping("/token")
	public ResponseEntity<Map<String, String>>  jwtToken(String grantType, String username, String password, boolean ambRefreshToken,
			String refreshToken) {
		
		String subject = null;
        String scope = null;
		if (grantType.equals("password")) {
			// authentificar user con authenticationManager
			org.springframework.security.core.Authentication authentication = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(username, password));
			subject = authentication.getName();
			scope = authentication.getAuthorities().stream().map(auth -> auth.getAuthority())
					.collect(Collectors.joining(" "));
		} else if (grantType.equals("refreshToken")) {
			if (refreshToken==null) {
				return new ResponseEntity<>(Map.of("error","refresh token required!!"),HttpStatus.UNAUTHORIZED);
			}
			
			Jwt decodeJWT;
			try {
				decodeJWT = jwtDecoder.decode(refreshToken);
			} catch (JwtException e) {
				return new ResponseEntity<>(Map.of("error",e.getMessage()),HttpStatus.UNAUTHORIZED);
			}
			subject = decodeJWT.getSubject();
			UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
			Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
			scope=authorities.stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));
		}

		Map<String, String> idToken = new HashMap<>();
		Instant instant = Instant.now();
		// generar los claims (revendicacions para nuestro jwt)
		JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder().subject(subject).issuedAt(instant)
				.expiresAt(instant.plus(ambRefreshToken ? 5 : 10, ChronoUnit.MINUTES)).issuer("seguritat-service")
				.claim("scope", scope).build();
		String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
		idToken.put("accessToken", jwtAccessToken);
		if (ambRefreshToken) {
			// generar los claims (revendicacions para nuestro jwt)
			JwtClaimsSet jwtClaimsSetRefresh = JwtClaimsSet.builder().subject(subject)
					.issuedAt(instant).expiresAt(instant.plus(30, ChronoUnit.MINUTES)).issuer("seguritat-service")
					// .claim("scope",scope)
					.build();
			String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
			idToken.put("refreshToken", jwtRefreshToken);
		}
		return new ResponseEntity<>(idToken,HttpStatus.OK);
	}

	// podemos ver lo que contiene el token en "jwt.io" site".

}
