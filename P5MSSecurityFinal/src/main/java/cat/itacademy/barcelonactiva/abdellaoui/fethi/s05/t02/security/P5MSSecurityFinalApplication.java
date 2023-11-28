package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppRole;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppUser;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.services.AccountService;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Config.RsaKeysConfiguration;

@EnableConfigurationProperties(RsaKeysConfiguration.class)
@EnableMethodSecurity
@SpringBootApplication
//@Slf4j
public class P5MSSecurityFinalApplication {

	public static void main(String[] args) {
		SpringApplication.run(P5MSSecurityFinalApplication.class, args);
	}

	@Bean
	CommandLineRunner star(AccountService accountService) {
		return args -> {

			accountService.addRole(new AppRole(null, "USER"));
			accountService.addRole(new AppRole(null, "PLAYER"));
			accountService.addRole(new AppRole(null, "PLAYER_MANAGER"));
			accountService.addRole(new AppRole(null, "ANONYMOUS"));
			accountService.addRole(new AppRole(null, "ADMIN"));

			accountService.addUser(new AppUser(null, "user1", "1234", new ArrayList<>()));
			accountService.addUser(new AppUser(null, "user2", "1234", new ArrayList<>()));
			accountService.addUser(new AppUser(null, "user3", "1234", new ArrayList<>()));
			accountService.addUser(new AppUser(null, "player_manager", "1234", new ArrayList<>()));
			accountService.addUser(new AppUser(null, "admin", "1234", new ArrayList<>()));

			accountService.addRoleToUser("admin", "ADMIN");
			accountService.addRoleToUser("admin", "USER");

			accountService.addRoleToUser("user1", "USER");
			accountService.addRoleToUser("user2", "USER");
			accountService.addRoleToUser("user3", "USER");

			accountService.addRoleToUser("player_manager", "PLAYER_MANAGER");
			accountService.addRoleToUser("player_manager", "USER");

		};
	}



}
