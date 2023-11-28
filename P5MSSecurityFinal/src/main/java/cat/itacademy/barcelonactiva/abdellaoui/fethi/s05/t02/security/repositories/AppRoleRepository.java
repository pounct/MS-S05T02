package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security.entities.AppRole;


public interface AppRoleRepository extends JpaRepository<AppRole, Long>{

	AppRole findByRolename(String rolename);
}
