package tande.house.usersapi.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import tande.house.usersapi.dto.*;
import tande.house.usersapi.model.User;
import tande.house.usersapi.repo.UserRepository;
import tande.house.usersapi.security.JwtUtil;
import tande.house.usersapi.security.UserPrincipal;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder encoder;
    private final JwtUtil jwt;

    @Value("${internal.serviceKey:}")
    private String internalServiceKey;

    @PostMapping("/register")
    public AuthResponse register(@Valid @RequestBody RegisterRequest req) {
        String email = req.getEmail().trim().toLowerCase();

        if (repo.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email ya existe");
        }

        User u = new User();
        u.setNombre(req.getNombre().trim());
        u.setEmail(email);
        u.setPassword(encoder.encode(req.getPassword()));
        u.setAdmin(false);

        u = repo.save(u);

        String token = jwt.createToken(u.getId(), u.getEmail(), u.isAdmin());

        return new AuthResponse(
                new AuthResponse.UserDto(u.getId(), u.getEmail(), u.isAdmin(), u.getNombre()),
                token
        );
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest req) {
        String email = req.getEmail().trim().toLowerCase();

        User u = repo.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas"));

        if (!encoder.matches(req.getPassword(), u.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas");
        }

        String token = jwt.createToken(u.getId(), u.getEmail(), u.isAdmin());

        return new AuthResponse(
                new AuthResponse.UserDto(u.getId(), u.getEmail(), u.isAdmin(), u.getNombre()),
                token
        );
    }

    @GetMapping("/me")
    public UserMeResponse me() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!(principal instanceof UserPrincipal p)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No autenticado");
        }

        User u = repo.findById(p.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No autenticado"));

        return new UserMeResponse(u.getId(), u.getEmail(), u.isAdmin(), u.getNombre());
    }

    @PostMapping("/internal/verify")
    public UserMeResponse internalVerify(
            @RequestHeader(value = "X-Internal-Key", required = false) String key,
            @RequestParam("token") String token
    ) {
        if (internalServiceKey != null && !internalServiceKey.isBlank()) {
            if (key == null || !internalServiceKey.equals(key)) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Forbidden");
            }
        }

        UserPrincipal p = jwt.verify(token);

        User u = repo.findById(p.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token inválido"));

        return new UserMeResponse(u.getId(), u.getEmail(), u.isAdmin(), u.getNombre());
    }
}
