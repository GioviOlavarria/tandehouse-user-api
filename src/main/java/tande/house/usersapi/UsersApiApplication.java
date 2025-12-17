package tande.house.usersapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "tande.house.usersapi")
public class UsersApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(UsersApiApplication.class, args);
    }
}
