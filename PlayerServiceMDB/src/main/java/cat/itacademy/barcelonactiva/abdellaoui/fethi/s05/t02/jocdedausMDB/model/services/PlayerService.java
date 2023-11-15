package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.services;

import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.Collections;

import org.springframework.stereotype.Service;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.mappers.PlayerMapper;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.mappers.GameMapper;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.domain.Game;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.domain.Player;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto.GameDTO;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto.PlayerDTO;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.repositories.GameRepository;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.repositories.PlayerRepository;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class PlayerService implements IPlayerService {

	private PlayerRepository playerRepository;
	private GameRepository gameRepository;

	static Random random() {
		
		return new Random();
	}

	
	@Override
	public List<PlayerDTO> getPlayers() {
		
		List<PlayerDTO> players = playerRepository.findAll()
				.stream()
				.map(PlayerMapper::toDTO)
				.toList();
		players.forEach(p -> p.setSuccessesPercentage(getPercentatge(p.getId())));
		
		return players;
	}

	
	@Override
	public PlayerDTO addPlayer(PlayerDTO playerDTO) {
		
		Player player = PlayerMapper.toPlayer(playerDTO);
		
		return PlayerMapper.toDTO(playerRepository.save(player));
	}

	
	@Override
	public PlayerDTO updatePlayer(String nom, PlayerDTO playerDTO) {
		
		Player player = PlayerMapper.toPlayer(playerDTO);
		player.setUsername(nom);
		
		return PlayerMapper.toDTO(playerRepository.save(player));
	}

	
	@Override
	public List<GameDTO> getPlayerGames(String id) {
		
		Optional<Player> player = playerRepository.findById(id);
		if (player.isPresent()) {
			
			return gameRepository.findByPlayer(player.get())
					.stream()
					.map(GameMapper::toDTO)
					.toList();
		}
		
		return Collections.emptyList();
	}

	
	@Override
	public GameDTO playGame(String id) {

		Optional<Player> player = playerRepository.findById(id);

		if (!player.isEmpty()) {

			Game game = new Game();
			game.setDice1((byte) (random().nextInt(6) + 1));
			game.setDice2((byte) (random().nextInt(6) + 1));
			game.setPlayer(player.get());
			
			return GameMapper.toDTO(gameRepository.save(game));
		}
		
		return null;
	}

	
	@Override
	public List<String> getUsernames() {

		return playerRepository.findAll()
				.stream()
				.map(Player::getUsername)
				.toList();
	}

	
	@Override
	public PlayerDTO getPlayerDTO(String id) {

		Optional<Player> p = playerRepository.findById(id);
		if (p.isPresent()) {
			
			PlayerDTO dto = PlayerMapper.toDTO(p.get());
			dto.setSuccessesPercentage(getPercentatge(id));
			
			return dto;
		}
		
		return null;
	}

	
	@Override
	public PlayerDTO deletePlayerGames(String id) {
		
		Optional<Player> player = playerRepository.findById(id);
		if (player.isPresent()) {
			List<Game> games = gameRepository.findByPlayer(player.get());
			gameRepository.deleteAll(games);
			
			return PlayerMapper.toDTO(player.get());
		}
		
		return null;
	}
	
	
	@Override
	public Float getPercentatge(String id) {
		
		Optional<Player> p = playerRepository.findById(id);
		if (p.isPresent()) {
			
			List<Game> games = gameRepository.findByPlayer(p.get());
			int won = 0;
			for (Game g : games) {
				if (Boolean.TRUE.equals(g.won())) {
					won++;
				}
			}
			
			return ((float) won * 100 / games.size());
		}
		
		return null;
	}
	
	@Override
	public Float getPercentatgeMitja() {
		
		List<Game> games = gameRepository.findAll();
		int won = 0;
		for (Game g : games) {
			
			if (Boolean.TRUE.equals(g.won())) {
				
				won++;
			}
		}
		
		return ((float) won * 100 / games.size());
	}
	
	@Override
	public Float getPercentatgeMitjaMitjor() {
		
		List<Player> players = playerRepository.findAll();
		float max = 0;
		for (Player p : players) {
			
			Float percent = getPercentatge(p.getId());
			if (percent > max) {
				
				max = percent;
			}
		}
		
		return max;
	}
	
	@Override
	public Float getPercentatgeMitjaPitjor() {
		
		List<Player> players = playerRepository.findAll();
		float min = 0;
		for (Player p : players) {
			
			Float percent = getPercentatge(p.getId());
			if (min > percent) {
				
				min = percent;
			}
		}
		
		return min;
	}
	
	
}
