package com.example.jocdedaus.model.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import com.example.jocdedaus.model.domain.Player;

@RepositoryRestResource(collectionResourceRel = "player", path = "player")
public interface PlayerRepository extends JpaRepository<Player, Long>{
}
