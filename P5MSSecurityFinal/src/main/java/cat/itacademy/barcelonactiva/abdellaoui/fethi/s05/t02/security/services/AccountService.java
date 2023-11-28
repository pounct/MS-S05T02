package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.services;

import java.util.List;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppRole;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppUser;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.repositories.AppRoleRepository;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.repositories.AppUserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;

@Service
@Transactional
@AllArgsConstructor
public class AccountService implements IAccountService {
	
	private AppUserRepository appUserRepository;
	private AppRoleRepository appRoleRepository;
	private PasswordEncoder passwordEncoder;
	
	

	@Override
	public AppUser addUser(AppUser appUser) {

		String pw = appUser.getPassword();
		appUser.setPassword(passwordEncoder.encode(pw));
		
		return appUserRepository.save(appUser);
	}
	

	
	@Override
	public AppUser addUserRegister(String username, String password, String confirmedPassword) {
		
		AppUser  user=appUserRepository.findByUsername(username);
        
		if(user!=null) throw new RuntimeException("User already exists");
		
        if(!password.equals(confirmedPassword)) throw new RuntimeException("Please confirm your password");
        
        AppUser appUser=new AppUser();
        appUser.setUsername(username);
        appUser.setPassword(passwordEncoder.encode(password));
        appUserRepository.save(appUser);
        
        addRoleToUser(username,"USER");
        
        return appUser;
	}

	@Override
	public AppRole addRole(AppRole appRole) {
		
		return appRoleRepository.save(appRole);
	}

	@Override
	public void addRoleToUser(String username, String rolename) {
		AppUser appUser = appUserRepository.findByUsername(username);
		AppRole appRole = appRoleRepository.findByRolename(rolename);

		appUser.getAppRoles().add(appRole);
	}

	@Override
	public AppUser getUserByUsername(String username) {
		
		return appUserRepository.findByUsername(username);
	}

	@Override
	public List<AppUser> getUsers() {
		
		return appUserRepository.findAll();
	}

	

	

}
