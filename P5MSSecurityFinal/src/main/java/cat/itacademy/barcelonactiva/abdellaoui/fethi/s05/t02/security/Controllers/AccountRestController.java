package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.Controllers;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppRole;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppUser;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.services.AccountService;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.services.AuthService;
import lombok.AllArgsConstructor;
import lombok.Data;

@RestController
@AllArgsConstructor
public class AccountRestController {

	private AccountService accountService;
	private AuthService authService;

	@GetMapping("/profile")
	public Authentication authentication(Authentication authentication) {

		return authentication;
	}

	@GetMapping("/users")
	public List<AppUser> getAllUsers() {

		return accountService.getUsers();
	}

	@PostMapping("/user")
	public AppUser addNewUser(@RequestBody AppUser appUser) {
		
		return accountService.addUser(appUser);
	}

	@PostMapping("/role")
	public AppRole addNewRole(@RequestBody AppRole appRole) {
		return accountService.addRole(appRole);
	}

	@PostMapping("/user/role")
	public void addRoleToUser(@RequestBody UserAndRole userAndRole) {
		
		accountService.addRoleToUser(userAndRole.getUsername(), userAndRole.getRolename());
	}

	@GetMapping("/user")
	public AppUser loadUserByUsername(@RequestBody String username) {
		
		return accountService.getUserByUsername(username);
	}
	
	@PostMapping("/register")
    public AppUser register(@RequestBody  UserForm userForm){
        return  accountService.addUserRegister(
                userForm.getUsername(),userForm.getPassword(),userForm.getConfirmedPassword());
    }
	
	@PostMapping("/login")
    public Map<String, String> login(@RequestBody  UserForm userForm){
		//return Map.of("message", "RestApi permitAll() work!");
        return  authService.loginUser(
                userForm.getUsername(),userForm.getPassword());
    }
}

@Data
class UserAndRole {
	
	private String username;
	private String rolename;
}

@Data
class UserForm{
    private String username;
    private String password;
    private String confirmedPassword;
}
