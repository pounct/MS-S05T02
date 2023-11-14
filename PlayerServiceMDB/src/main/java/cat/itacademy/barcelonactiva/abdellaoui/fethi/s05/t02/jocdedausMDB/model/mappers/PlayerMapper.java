package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.mappers;

import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.domain.Player;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto.PlayerDTO;


public class PlayerMapper {

	public static PlayerDTO toDTO(Player player) {

		return PlayerDTO.builder()
				.id(player.getId())
				.username(player.getUsername())
				.registrationDate(player.getRegistrationDate())
				.build();
	}
	
	public static Player toPlayer(PlayerDTO dto) {

		return Player.builder()
				.id(dto.getId())
				.username(dto.getUsername())
				.registrationDate(dto.getRegistrationDate())
				.build();
	}

}
