package io.getarrays.jwtstudy2.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

// 요청 필터당 하나만 존재하는 필터이기 때문에 application 으로 들어오는 모든 요청을 여기에서 가로챕니다.
// 그리고, 사용자가 application 자원에 access 권한이 있는지를 논리적으로 처리해주면 된다.
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 1. 로그인 경로인지 확인 (login 은 여기에서 작업할 필요가 없기 때문.) == 아무일도 하지않을거임.
        if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
            filterChain.doFilter(request, response);
        } else {
            // 2. 권한 부여 헤더에 access
            // 헤더를 가져온 다음 내가 찾고 있는 키를 전달하고, 인증 키를 찾음
            String authorizationHeader = request.getHeader(AUTHORIZATION);

            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                try {
                    // token 검증 작업
                    String token = authorizationHeader.substring("Bearer ".length());
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); // 토큰 생성할 때와 같은 알고리즘으로 풀어야함.
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = verifier.verify(token);

                    // 토큰이 유효한지 확인되면, 사용자의 이름을 가져올 수 있습니다.
                    String username = decodedJWT.getSubject(); // token 과 함께 제공되는 사용자 이름을 줍니다.
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class); // token 의 roles 를 파싱하여 들고옴(json 배열로 되있음.)
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    stream(roles).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    });

                    // 암호가 필요없는 이유는 token 검증을 끝마쳤기 때문에 이미 유효한 token 으로 인증이 된 사용자이다.
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);

                    // SpringSecurity 를 호출한 다음 Context 를 들고와서 인증을 설정한 다음 인증 토큰을 전달합니다.
                    // ex) Security 야! 사용자이름과, 역할(role) 등등이 여기있으니 들고가서 access 할 수 있는 자원도 결정해주고 뭐 알아서 하렴 !
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    filterChain.doFilter(request, response);
                } catch (Exception exception) {
                    // exception 1 : token 이 유효하지 않을 때 (token 을 확인할 수 없거나, 유효기간이 지났을 경우)
                    log.error("Error logging in: {}", exception.getMessage());
                    response.setHeader("error", exception.getMessage());

                    /* error 를 403 으로 던지기 (둘중 하나만 할 수 있음) */
//                    response.sendError(FORBIDDEN.value()); // 권한이 없기 때문에 403 던져버리기~!

                    /* error 를 body 로 던지기 (둘중 하나만 할 수 있음) */
                    response.setStatus(FORBIDDEN.value());
                    Map<String, String> error = new HashMap<>();
                    error.put("error_message", exception.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);

                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
