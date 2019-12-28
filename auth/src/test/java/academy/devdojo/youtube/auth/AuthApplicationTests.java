package academy.devdojo.youtube.auth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class AuthApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void name() {
		System.out.println(new BCryptPasswordEncoder().encode("devdojo"));
	}
}
