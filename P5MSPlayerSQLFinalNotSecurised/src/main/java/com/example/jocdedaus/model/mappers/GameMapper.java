package com.example.jocdedaus.model.mappers;

import com.example.jocdedaus.model.domain.Game;
import com.example.jocdedaus.model.dto.GameDTO;

public class GameMapper {

	private GameMapper() {
	    throw new IllegalStateException("Utility class");
	  }
	
	public static GameDTO toDTO(Game game) {

		return GameDTO.builder()
				.id(game.getId())
				.dice1(game.getDice1())
				.dice2(game.getDice2())
				.won(game.won())
				.build();
	}

	public static Game toGame(GameDTO gameDTO) {
		
		return Game.builder()
				.id(gameDTO.getId())
				.dice1(gameDTO.getDice1())
				.dice2(gameDTO.getDice2())
				.build();
	}
}
