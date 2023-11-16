package com.example.jocdedaus.model.dto;

import java.time.LocalDateTime;

import lombok.Builder;
import lombok.Data;

@Data @Builder
public class PlayerDTO {

	private Long id;
	private String username;
	private LocalDateTime registrationDate;
	private Float percentatgedExit;
}
