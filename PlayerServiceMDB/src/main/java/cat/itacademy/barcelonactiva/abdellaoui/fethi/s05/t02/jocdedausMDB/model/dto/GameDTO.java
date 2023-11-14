package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.dto;

import lombok.Builder;
import lombok.Data;

@Data @Builder
public class GameDTO {
	
	private String id;
	private Byte dice1;
	private Byte dice2;	
	private Boolean won;
}
