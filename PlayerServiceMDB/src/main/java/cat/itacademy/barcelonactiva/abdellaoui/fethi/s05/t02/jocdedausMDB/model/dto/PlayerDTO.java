package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto;


import java.time.LocalDate;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PlayerDTO {
	
	private String id;
	private String username;
	private LocalDate registrationDate;
	private Float successesPercentage;
}
