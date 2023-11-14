package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.repositories;

import org.springframework.data.mongodb.repository.MongoRepository;
import cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.jocdedausMDB.model.domain.Player;

public interface PlayerRepository extends MongoRepository<Player, String>{

}
