package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.domain;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.DocumentReference;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Document
@Data @AllArgsConstructor @NoArgsConstructor @ToString @Builder
public class Game {	
	@Id
	private String id;	
	private Byte dice1;	
	private Byte dice2;
	
	@DocumentReference(lazy=true)
	private Player player;
	
	public Boolean won() {
		return (dice1+dice2==7);
	}
	
}
