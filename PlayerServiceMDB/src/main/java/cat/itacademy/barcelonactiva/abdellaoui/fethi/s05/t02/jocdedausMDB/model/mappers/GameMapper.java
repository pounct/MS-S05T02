package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.mappers;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.domain.Game;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto.GameDTO;

public class GameMapper {

	public static GameDTO toDTO(Game game) {

		return GameDTO.builder()
				.id(game.getId())
				.dice1(game.getDice1())
				.dice2(game.getDice2())
				.won(game.won()).build();
	}

	public static Game toGame(GameDTO gameDTO) {
		// TODO Auto-generated method stub
		return Game.builder()
				.id(gameDTO.getId())
				.dice1(gameDTO.getDice1())
				.dice2(gameDTO.getDice2())
				.build();
	}

}
