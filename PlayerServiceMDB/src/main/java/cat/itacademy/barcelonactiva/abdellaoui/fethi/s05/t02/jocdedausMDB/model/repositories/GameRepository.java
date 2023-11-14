package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.repositories;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.domain.Game;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.domain.Player;

public interface GameRepository extends MongoRepository<Game, String>{

	List<Game> findByPlayer(Player player);
	
}
