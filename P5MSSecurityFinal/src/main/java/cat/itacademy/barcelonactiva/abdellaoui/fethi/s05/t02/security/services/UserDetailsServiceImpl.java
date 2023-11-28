package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.services;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppUser;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    
    private AccountService accountService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    	
        AppUser appUser = accountService.getUserByUsername(username);
        if(appUser==null) throw new UsernameNotFoundException(String.format("User %s not fount",username));
        
        Collection<GrantedAuthority> authorities=new ArrayList<>();
        appUser.getAppRoles()
        .forEach(role -> authorities
        		.add(new SimpleGrantedAuthority(role.getRolename())));
        UserDetails user = User //.withDefaultPasswordEncoder()
        		.withUsername(appUser.getUsername())
        		.password(appUser.getPassword())
        		.authorities(authorities)
        		.build();
        return user;
    }
}
