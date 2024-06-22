package dev.oshara.jwt_demo.filters;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import java.util.List;

@Getter
@Setter
@EqualsAndHashCode(callSuper = false)
public class AdAuthToken extends JwtAuthenticationToken {
    private String email;
    private List<GrantedAuthority> authorities;
    public AdAuthToken(JwtAuthenticationToken jwtAuthenticationToken) {
        super(jwtAuthenticationToken.getToken(), jwtAuthenticationToken.getAuthorities());
    }
}
