package com.example.jocdedaus.model.services;

import java.util.List;
import java.util.Optional;
import java.util.Random;

import org.springframework.stereotype.Service;

import com.example.jocdedaus.model.domain.Game;
import com.example.jocdedaus.model.domain.Player;
import com.example.jocdedaus.model.dto.GameDTO;
import com.example.jocdedaus.model.dto.PlayerDTO;
import com.example.jocdedaus.model.mappers.GameMapper;
import com.example.jocdedaus.model.mappers.PlayerMapper;
import com.example.jocdedaus.model.repositories.GameRepository;
import com.example.jocdedaus.model.repositories.PlayerRepository;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class PlayerService implements IPlayerService{

	private PlayerRepository playerRepository;
	private GameRepository gameRepository;

	static Random random() {
		return new Random();
	}

	@Override
	public PlayerDTO addPlayer(PlayerDTO pdto) {
		Player player = playerRepository.save(PlayerMapper.toPlayer(pdto));
		return PlayerMapper.toDTO(player);
	}

	@Override
	public PlayerDTO updatePlayer(String nom, PlayerDTO playerDTO) {
		Optional<Player> player = playerRepository.findById(playerDTO.getId());
		if (player.isPresent()) {
			Player result = player.get();
			// only username can be changed for Player client
			result.setUsername(nom);
			playerRepository.save(result);
			return PlayerMapper.toDTO(result);
		}
		return null;
	}

	@Override
	public void deletePlayerGames(Long playerId) {
		
		List<Game> games = gameRepository.findAllByPlayerId(playerId);
		gameRepository.deleteAll(games);
	}

	@Override
	public List<PlayerDTO> getAllPlayers() {

		List<Player> players = playerRepository.findAll();
		List<PlayerDTO> playersDTO = players.stream().map(PlayerMapper::toDTO).toList();
		playersDTO.forEach(p -> p.setPercentatgedExit(getPercentatge(p.getId())));
		return playersDTO;
	}

	@Override
	public List<GameDTO> getPlayerGames(Long playerId) {

		return gameRepository.findAllByPlayerId(playerId).stream().map(GameMapper::toDTO).toList();
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

	@Override
	public Float percentatgedExit(List<Game> playerGames) {
		Integer tiradesGuanyades = 0;
		if (!playerGames.isEmpty()) {
			for (Game t : playerGames) {
				if (Boolean.TRUE.equals(t.won())) {
					tiradesGuanyades += 1;
				}
			}
			return ((float) tiradesGuanyades / playerGames.size() * 100);
		}
		return null;
	}

	@Override
	public List<String> getUsernames() {

		return playerRepository.findAll().stream().map(Player::getUsername).toList();
	}

	@Override
	public PlayerDTO getPlayerDTO(Long id) {

		Optional<Player> p = playerRepository.findById(id);
		if (p.isPresent()) {
			PlayerDTO dto = PlayerMapper.toDTO(p.get());
			dto.setPercentatgedExit(getPercentatge(id));
			return dto;
		}
		return null;
	}

	@Override
	public Float getPercentatge(Long id) {
		List<Game> games = gameRepository.findAllByPlayerId(id);
		int won = 0;
		for (Game g : games) {
			if (Boolean.TRUE.equals(g.won())) {
				won++;
			}
		}
		return ((float) won * 100 / games.size());
	}

	@Override
	public GameDTO playGame(Long playerid) {

		Optional<Player> player = playerRepository.findById(playerid);
		if (player.isPresent()) {

			Game game = new Game();
			game.setDice1((byte) (random().nextInt(6) + 1));
			game.setDice2((byte) (random().nextInt(6) + 1));
			game.setPlayer(player.get());

			gameRepository.save(game);
			return GameMapper.toDTO(game);
		}
		return null;
	}

}
