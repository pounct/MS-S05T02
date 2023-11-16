package com.example.jocdedaus.controllers;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.jocdedaus.model.dto.GameDTO;
import com.example.jocdedaus.model.dto.PlayerDTO;
import com.example.jocdedaus.model.dto.PlayerDTOContext;
import com.example.jocdedaus.model.services.PlayerService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/players")
@AllArgsConstructor
public class PlayerController {

	PlayerService playerService;

	static final String ANONIM = "ANÒNIM";
	@PostMapping
	public ResponseEntity<PlayerDTO> addPlayer(@RequestBody PlayerDTO playerDTO) {

		String username = playerDTO.getUsername();
		List<String> usernames = playerService.getUsernames();
		if (usernames.contains(username) && (!username.equalsIgnoreCase(ANONIM))) {
			return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
		}
		if (username == null || "".equals(username)) {
			playerDTO.setUsername(ANONIM);
		}
		playerDTO.setRegistrationDate(LocalDateTime.now());
		PlayerDTO playerDTOResult = playerService.addPlayer(playerDTO);
		return new ResponseEntity<>(playerDTOResult, HttpStatus.OK);
	}

	@PutMapping
	public ResponseEntity<PlayerDTO> updatePlayer(@RequestBody PlayerDTOContext playerDTOContext) {

		String newUsername = playerDTOContext.getNom();
		PlayerDTO playerDTO = playerDTOContext.getPlayerDTO();

		PlayerDTO pdto = playerService.getPlayerDTO(playerDTO.getId());

		if (pdto == null) {

			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		List<String> usernames = playerService.getUsernames();

		if (usernames.contains(newUsername) && (!newUsername.equalsIgnoreCase(ANONIM))) {

			return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
		}
		if (newUsername == null || "".equals(newUsername)) {

			playerDTO.setUsername(ANONIM);
		}
		PlayerDTO result = playerService.updatePlayer(newUsername, playerDTO);
		return new ResponseEntity<>(result, HttpStatus.OK);
	}

	@GetMapping
	ResponseEntity<List<PlayerDTO>> getAllPlayers() {
		return new ResponseEntity<>(playerService.getAllPlayers(), HttpStatus.OK);
	}

	@PostMapping("/{id}/games")
	public ResponseEntity<GameDTO> playGame(@PathVariable Long id) {
		PlayerDTO pdto = playerService.getPlayerDTO(id);
		if (pdto == null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		GameDTO game = playerService.playGame(id);
		return new ResponseEntity<>(game, HttpStatus.CREATED);
	}

	@DeleteMapping("/{id}/games")
	public ResponseEntity<PlayerDTO> deleteAllGames(@PathVariable Long id) {
		PlayerDTO pdto = playerService.getPlayerDTO(id);
		if (pdto == null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		playerService.deletePlayerGames(id);
		pdto = playerService.getPlayerDTO(id);
		return new ResponseEntity<>(pdto, HttpStatus.OK);
	}

	@GetMapping("/{id}/games")
	public ResponseEntity<List<GameDTO>> getPlayerGames(@PathVariable Long id) {
		PlayerDTO pdto = playerService.getPlayerDTO(id);
		if (pdto == null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		return new ResponseEntity<>(playerService.getPlayerGames(id), HttpStatus.OK);
	}

	@GetMapping("/ranking")
	public ResponseEntity<Float> getPercentatgeMitja() {
		return new ResponseEntity<>(playerService.getPercentatgeMitja(), HttpStatus.OK);
	}

	@GetMapping("/ranking/winner")
	public ResponseEntity<Float> getPercentatgeMitjaMitjor() {
		return new ResponseEntity<>(playerService.getPercentatgeMitjaMitjor(), HttpStatus.OK);
	}

	@GetMapping("/ranking/loser")
	public ResponseEntity<Float> getPercentatgeMitjaPitjor() {
		return new ResponseEntity<>(playerService.getPercentatgeMitjaPitjor(), HttpStatus.OK);
	}
}
