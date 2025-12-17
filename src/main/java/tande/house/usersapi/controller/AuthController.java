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

    @Value("${app.admin.code:}")
    private String adminCode;

    private static UserMeResponse toMe(User u) {
        return new UserMeResponse(u.getId(), u.getEmail(), u.isAdmin(), u.getNombre());
    }

    @PostMapping("/register")
    public AuthResponse register(@Valid @RequestBody RegisterRequest req) {
        String email = req.getEmail().trim().toLowerCase();

        if (repo.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email ya existe");
        }

        boolean makeAdmin = Boolean.TRUE.equals(req.getAdmin());
        if (makeAdmin) {
            if (adminCode == null || adminCode.isBlank()) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Registro admin deshabilitado");
            }
            String provided = req.getAdminCode() == null ? "" : req.getAdminCode();
            if (!adminCode.equals(provided)) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Código administrador incorrecto");
            }
        }

        User u = new User();
        u.setNombre(req.getNombre().trim());
        u.setEmail(email);
        u.setPasswordHash(encoder.encode(req.getPassword()));
        u.setAdmin(makeAdmin);

        u = repo.save(u);

        String token = jwt.createToken(u.getId(), u.getEmail(), u.isAdmin());
        return new AuthResponse(token, toMe(u));
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest req) {
        String email = req.getEmail().trim().toLowerCase();

        User u = repo.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas"));

        if (!encoder.matches(req.getPassword(), u.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas");
        }

        String token = jwt.createToken(u.getId(), u.getEmail(), u.isAdmin());
        return new AuthResponse(token, toMe(u));
    }

    @GetMapping("/me")
    public UserMeResponse me() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!(principal instanceof UserPrincipal p)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No autenticado");
        }

        User u = repo.findById(p.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No autenticado"));

        return toMe(u);
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

        return toMe(u);
    }
}
