package tande.house.usersapi.security;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserPrincipal {
    private Long userId;
    private String email;
    private boolean admin;
}
