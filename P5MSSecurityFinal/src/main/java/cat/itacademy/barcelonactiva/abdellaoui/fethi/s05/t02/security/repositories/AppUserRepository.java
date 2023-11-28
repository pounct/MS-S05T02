package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppUser;


public interface AppUserRepository extends JpaRepository<AppUser, Long>{

	AppUser findByUsername(String username);
}
