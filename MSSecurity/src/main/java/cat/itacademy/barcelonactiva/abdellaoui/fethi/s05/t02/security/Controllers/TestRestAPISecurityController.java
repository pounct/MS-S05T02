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

	// autotificació predeterminada al Spring-security
		// podemos ejecutar la aplicacio
		// Spring ens proporciona una contrasenya per accedir com:
		// Using generated security password: 9e1b2716-2885-43df-abc8-884bac4cccd8

		@GetMapping("/RestApi")
		public Map<String, Object> dadaTest() {
			return Map.of("message", "prova de dades1");
		}

		// vamos a usar y configurar una autotificacio de tipo stateless
		// statefull : lado servidor usando sesion y cookies
		// stateless : enregistrar la session en un token lliurat al client
		// crear package config en que creamos la classe de configuracio
		// "SeguretatConfig"
		// i ....

		// podemos usar el token recibido para el test amb postman
		@GetMapping("/dada")
		@PreAuthorize("hasAuthority('SCOPE_USER')")
		public Map<String, Object> dataTest(Authentication authentication) {
			return Map.of("message", "prova de dades2", "username", authentication.getName(), "authorities",
					authentication.getAuthorities());
		}

		// podemos usar el token recibido para el test amb postman
		@PostMapping("/saveDada")
		@PreAuthorize("hasAuthority('SCOPE_ADMIN')")
		public Map<String, String> saveDadaTest(String dada) {
			return Map.of("dadaSaved", dada);
		}
}
