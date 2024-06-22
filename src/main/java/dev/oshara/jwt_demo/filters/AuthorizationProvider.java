package dev.oshara.jwt_demo.filters;

import dev.oshara.jwt_demo.controller.HomeController;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

@Getter
@Setter
@Component
public class AuthorizationProvider extends OncePerRequestFilter {
    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationProvider.class);

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        LOG.info("AuthorizationProvider: doFilterInternal");
        JwtAuthenticationToken jwtAuthentication = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        AdAuthToken authentication = new AdAuthToken(jwtAuthentication);
//        authentication.setAuthorities(List.of(new SimpleGrantedAuthority("test:read")));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
