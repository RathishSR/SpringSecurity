package com.campercodes.springSecurity.filter;

import com.campercodes.springSecurity.entity.User;
import com.campercodes.springSecurity.service.JwtService;
import com.campercodes.springSecurity.service.UserService;
import com.mysql.cj.util.StringUtils;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String BEARER = "Bearer ";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final Integer SEVEN = 7;



    @Autowired
    private JwtService jwtUtil;

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        if(authHeader != null && authHeader.startsWith(BEARER)) {
            String jwt = authHeader.substring(SEVEN);
            String username = null;
            try {
                username = jwtUtil.extractSubject(jwt);
            } catch (Exception e) {
                log.info("Extract username: Invalid token");
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.getWriter().write("Invalid token provided");
                return;
            }

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                User user = userService.loadUserByUsername(username);
                boolean isTokenValid = false;
                try {
                    isTokenValid = jwtUtil.isTokenValid(jwt, user);
                } catch (ExpiredJwtException e) {
                    String expiredToken = "Expired token";
                    log.info(expiredToken);
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.getWriter().write(e.getMessage());
                    return;
                } catch(Exception e) {
                    String invalidToken = "Invalid token";
                    log.info(invalidToken);
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.getWriter().write(
                            StringUtils.split(e.getMessage(),
                                    "Exception: ",
                                    true).get(1));
                    return;
                }
                if (isTokenValid) {
                    UsernamePasswordAuthenticationToken authToken
                            = new UsernamePasswordAuthenticationToken(
                            user.getUsername(), null, user.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        }
        filterChain.doFilter(request,response);
    }
}
