package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.services;

import java.util.List;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppRole;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppUser;

public interface IAccountService {
	
	AppUser addUser(AppUser appUser);
	
	AppUser addUserRegister(String username, String password, String confirmedPassword);
	
	AppRole addRole(AppRole appRole);

	void addRoleToUser(String username, String rolename);
	
	AppUser getUserByUsername(String username);
	
	List<AppUser> getUsers();
}
