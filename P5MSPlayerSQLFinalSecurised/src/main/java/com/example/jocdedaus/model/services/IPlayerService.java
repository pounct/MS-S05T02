package com.example.jocdedaus.model.services;

import java.util.List;

import com.example.jocdedaus.model.domain.Game;
import com.example.jocdedaus.model.dto.GameDTO;
import com.example.jocdedaus.model.dto.PlayerDTO;

public interface IPlayerService {
	PlayerDTO addPlayer(PlayerDTO pdto);
	PlayerDTO updatePlayer(String nom, PlayerDTO playerDTO);
	GameDTO playGame(Long playerid);
	void deletePlayerGames(Long playerId);
	List<PlayerDTO> getAllPlayers();
	List<GameDTO> getPlayerGames(Long playerId);
	Float getPercentatgeMitja();
	Float getPercentatgeMitjaMitjor();
	Float getPercentatgeMitjaPitjor();	
	Float percentatgedExit(List<Game> playerGames);
	List<String> getUsernames();
	PlayerDTO getPlayerDTO(Long id);
	Float getPercentatge(Long id);
}
