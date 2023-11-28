package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.services.AuthService;
import lombok.AllArgsConstructor;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class SecurityRestController {
	
	private AuthService authService;

	@PostMapping("/token")
	public ResponseEntity<Map<String, String>> jwtToken(String grantType, String username, String password,
			boolean ambRefreshToken, String refreshToken) {
		

		return new ResponseEntity<>(
				authService.authenticate(grantType, username, password, ambRefreshToken, refreshToken)
				, HttpStatus.OK);
	}
}