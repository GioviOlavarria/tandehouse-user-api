package tande.house.usersapi.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwt;


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path == null) return false;
        return path.startsWith("/auth/login")
                || path.startsWith("/auth/register")
                || path.startsWith("/auth/internal")
                || path.startsWith("/flow") || "OPTIONS".equalsIgnoreCase(request.getMethod())
                || "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7).trim();
            try {
                UserPrincipal p = jwt.verify(token);
                var auth = new UsernamePasswordAuthenticationToken(p, null, List.of());
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception ignored) {
            }
        }

        filterChain.doFilter(request, response);
    }
}
