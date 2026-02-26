package com.vshare.vshare.filter;

import com.vshare.vshare.feature.user.control.JwtService;
import com.vshare.vshare.feature.user.control.UserDetailService;
import com.vshare.vshare.feature.user.repo.UserRepo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final ApplicationContext context;

    private final UserRepo userRepo;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (byPassEndpointHandler(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = null;
        String username = null;
        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"Unauthorized");
            return;
        }

        token = header.substring(7);
        username = jwtService.extractUserName(token);

        // haven't authenticate with spring security
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = context.getBean(UserDetailService.class).loadUserByUsername(username);

            if(jwtService.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }

        filterChain.doFilter(request, response);
    }

    public boolean byPassEndpointHandler(HttpServletRequest request) throws ServletException, IOException {
        List<String> endpoints = new ArrayList<>();
        endpoints.add("/users/login");
        endpoints.add("/users/register");
        endpoints.add("/users/test");

        String url = request.getRequestURI();

        for(String endpoint : endpoints) {
            if (url.contains(endpoint)) return true;
        }
        return false;

    }

}

