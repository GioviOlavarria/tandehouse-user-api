package tande.house.usersapi.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserMeResponse {
    private Long userId;
    private String email;
    private boolean admin;
    private String nombre;
}