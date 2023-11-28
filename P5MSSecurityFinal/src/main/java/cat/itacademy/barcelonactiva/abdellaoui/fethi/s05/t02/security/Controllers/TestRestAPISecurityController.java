package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Controllers;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestRestAPISecurityController {

		@GetMapping("/RestApi")
		public Map<String, Object> dadaTest() {
			
			return Map.of("message", "RestApi permitAll() work!");
		}

		@GetMapping("/profile")
		@PreAuthorize("hasAuthority('SCOPE_USER')")
		public Map<String, Object> dataTest(Authentication authentication) {
			
			return Map.of("message", "get Profile with SCOPE_USER"
					, "username", authentication.getName()
					, "authorities", authentication.getAuthorities());
		}
		
		@PostMapping("/admin")
		@PreAuthorize("hasAuthority('SCOPE_ADMIN')")
		public Map<String, String> saveDadaTest(String dada) {
			
			return Map.of("message", "save data with SCOPE_ADMIN","dadaSaved", dada);
		}
}
