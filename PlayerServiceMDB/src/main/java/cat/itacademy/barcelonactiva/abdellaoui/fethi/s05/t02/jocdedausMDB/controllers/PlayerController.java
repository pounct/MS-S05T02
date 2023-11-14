package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.controllers;

import java.time.LocalDate;
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

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto.PlayerDTOContext;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto.GameDTO;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto.PlayerDTO;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.services.PlayerService;
import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
@RequestMapping("/players")
public class PlayerController {
	
	private PlayerService playerService;	
	
	
	@GetMapping
	List<PlayerDTO> getPlayers(){ 
		
		return playerService.getPlayers();
		
	}
	
	
	@PostMapping
	ResponseEntity<PlayerDTO> addPlayer(@RequestBody PlayerDTO playerDTO){
		
		String username = playerDTO.getUsername();
		List<String> usernames = playerService.getUsernames();
		
		if(usernames.contains(username)) {
			if (!username.equalsIgnoreCase("ANÒNIM")) {
				return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
			}
		}
		if (username==null || username == "") { 
			playerDTO.setUsername("ANÒNIM");
		}
		playerDTO.setRegistrationDate(LocalDate.now());
				
		return new ResponseEntity<>(playerService.addPlayer(playerDTO),HttpStatus.OK);
		
	}
	
	
	@PutMapping
	public ResponseEntity<PlayerDTO> updatePlayer(@RequestBody PlayerDTOContext playerDTOContext) {
		
		PlayerDTO playerDTO = playerDTOContext.getPlayerDTO();
		String newUsername = playerDTOContext.getNom();
		PlayerDTO pdto = playerService.getPlayerDTO(playerDTO.getId());
		
		if (pdto == null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		List<String> usernames = playerService.getUsernames();
		
		if(usernames.contains(newUsername)) {
			if (!newUsername.equalsIgnoreCase("ANÒNIM")) {				
				return new ResponseEntity<>(HttpStatus.BAD_REQUEST);			
			}			
		}
		if (newUsername==null || newUsername == "") { 
			playerDTO.setUsername("ANÒNIM");
		}
		return new ResponseEntity<>(playerService.updatePlayer(newUsername, playerDTO), HttpStatus.OK);

	}
	
	
	@GetMapping("{id}/games")
	public ResponseEntity<List<GameDTO>> getPlayerGames(@PathVariable String id){
		
		PlayerDTO pdto = playerService.getPlayerDTO(id);
		if (pdto == null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		return new ResponseEntity<>(playerService.getPlayerGames(id),HttpStatus.OK);
		
	}
	
	
	@PostMapping("{id}/games")
	public ResponseEntity<GameDTO> playGame(@PathVariable String id){
		
		PlayerDTO pdto = playerService.getPlayerDTO(id);
		if (pdto == null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}		
		return new ResponseEntity<>(playerService.playGame(id),HttpStatus.OK);
		
	}
	
	
	@DeleteMapping("/{id}/games")
	public ResponseEntity<PlayerDTO> deleteAllGames(@PathVariable String id){

		PlayerDTO pdto = playerService.getPlayerDTO(id);
		if (pdto == null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		return new ResponseEntity<>(playerService.deletePlayerGames(id),HttpStatus.OK);
	}

}
