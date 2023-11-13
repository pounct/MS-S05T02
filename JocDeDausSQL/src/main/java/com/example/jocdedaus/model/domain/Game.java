package com.example.jocdedaus.model.domain;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Data @AllArgsConstructor @NoArgsConstructor @ToString @Builder
public class Game {	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	@Min(value = 1) @Max(value = 6)
	private Byte dice1;
	@Min(value = 1) @Max(value = 6)
	private Byte dice2;	
	
	@ManyToOne(cascade = CascadeType.PERSIST)
	private Player player;
	
	public Boolean won() {
		return (dice1+dice2==7);
	}
	
}
