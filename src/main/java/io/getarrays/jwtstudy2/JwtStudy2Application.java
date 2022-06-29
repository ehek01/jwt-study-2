package io.getarrays.jwtstudy2;

import io.getarrays.jwtstudy2.entity.Role;
import io.getarrays.jwtstudy2.entity.User;
import io.getarrays.jwtstudy2.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtStudy2Application {
	/**
	 * TODO 2 : access token, refresh token 까지 정상발급 완료하였고, 이제 우리는 사용자로부터 발급해준 access token 을 가져와
	 * 			application 에 대한 액세스 권한을 부여하는 것입니다. 따라서, 사용자가 이 토큰을 인증으로 제공할 때마다
	 * 			이 token 을 확인한 다음 유효기간이 남아있다면, application 에 허용할 수 있어야 합니다.
	 *			그리고 이를 위해서는 인증 필터라는 것을 생성해야 합니다. 이 필터는 application 에 들어오는 모든 요청을 가로채고,
	 *			해당 특정 토큰을 찾아서 처리한 다음 사용자가 특정 자원에 액세스 할 수 있는지 여부를 결정해 줍니다.
	 *
	 *	TODO 3 : 로그인을 새로 했다면 기존 토큰은 폐기가 되어야 하는데 자꾸 사용이 가능하네?? 뭐가 문젤까....
	 */

	public static void main(String[] args) {
		SpringApplication.run(JwtStudy2Application.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(); // password Encoding 방식
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(null, "John Travolta", "john", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Will Smith", "will", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Jim Carry", "jim", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Arnold Schwarzenegger", "arnold", "1234", new ArrayList<>()));

			userService.addRoleToUser("john", "ROLE_USER");
			userService.addRoleToUser("john", "ROLE_MANAGER");
			userService.addRoleToUser("will", "ROLE_MANAGER");
			userService.addRoleToUser("jim", "ROLE_ADMIN");
			userService.addRoleToUser("arnold", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("arnold", "ROLE_ADMIN");
			userService.addRoleToUser("arnold", "ROLE_USER");

		};
	}

}
