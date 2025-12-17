package tande.house.usersapi.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class RegisterRequest {

    @NotBlank @Size(min = 2, max = 80)
    private String nombre;

    @NotBlank @Email @Size(max = 120)
    private String email;

    @NotBlank @Size(min = 6, max = 72)
    private String password;


    private Boolean admin;


    private String adminCode;
}
