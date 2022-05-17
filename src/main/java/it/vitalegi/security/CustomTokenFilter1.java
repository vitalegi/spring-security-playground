package it.vitalegi.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class CustomTokenFilter1 extends OncePerRequestFilter {
	Logger log = LoggerFactory.getLogger(this.getClass());

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		log.info("Apply token filter 1");
		// Get authorization header and validate
		final String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (header == null || !header.startsWith("Bearer ")) {
			log.info("Not valid header");
			chain.doFilter(request, response);
			return;
		}

		// Get jwt token and validate
		final String token = header.split(" ")[1].trim();
		if (!validate(token)) {
			log.info("Not valid header content");
			chain.doFilter(request, response);
			return;
		}

		Collection<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(getAuthority(token));
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(getUsername(token),
				token, authorities);

		authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		log.info("Authenticated!");
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
	}

	protected boolean validate(String token) {
		String[] values = token.split("\\.");
		return values.length == 2;
	}

	protected String getUsername(String token) {
		String[] values = token.split("\\.");
		if (values.length != 2) {
			throw new IllegalArgumentException("Len don't match");
		}
		return values[0];
	}

	protected GrantedAuthority getAuthority(String token) {
		String[] values = token.split("\\.");
		if (values.length != 2) {
			throw new IllegalArgumentException("Len don't match");
		}
		return new SimpleGrantedAuthority(values[1]);
	}

}