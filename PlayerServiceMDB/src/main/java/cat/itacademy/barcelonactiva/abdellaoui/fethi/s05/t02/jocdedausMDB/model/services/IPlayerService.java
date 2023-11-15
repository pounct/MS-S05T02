package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.services;

import java.util.List;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto.GameDTO;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto.PlayerDTO;

public interface IPlayerService {

	List<PlayerDTO> getPlayers();
	PlayerDTO addPlayer(PlayerDTO playerDTO);
	PlayerDTO updatePlayer(String nom, PlayerDTO playerDTO);
	List<GameDTO> getPlayerGames(String id);
	GameDTO playGame(String id);
	List<String> getUsernames();
	PlayerDTO getPlayerDTO(String id);
	PlayerDTO deletePlayerGames(String id);
	Float getPercentatge(String id);
	Float getPercentatgeMitja();
	Float getPercentatgeMitjaMitjor();
	Float getPercentatgeMitjaPitjor();
}
