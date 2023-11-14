package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.domain;

import java.time.LocalDate;
import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Document
@Data @AllArgsConstructor @NoArgsConstructor @ToString @Builder
public class Player {
	
	@Id
	private String id;
	private String username;
	private LocalDate registrationDate;
	@DBRef
	private List<Game> games;

}
