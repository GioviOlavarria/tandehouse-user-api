package tande.house.usersapi.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AuthResponse {
    private UserDto user;
    private String token;

    @Getter
    @AllArgsConstructor
    public static class UserDto {
        private Long id;
        private String email;
        private boolean admin;
        private String nombre;
    }
}
