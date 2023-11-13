package com.example.jocdedaus.model.mappers;

import com.example.jocdedaus.model.dto.PlayerDTO;

import com.example.jocdedaus.model.domain.Player;

public class PlayerMapper {
	
	private PlayerMapper() {
		throw new IllegalStateException("Utility class");
	}

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
