package it.vitalegi.security;

import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	Logger log = LoggerFactory.getLogger(this.getClass());

	@Autowired
	protected CustomTokenFilter1 authFilter1;

	@Autowired
	protected CustomTokenFilter2 authFilter2;

	@Value("${security.http.content-security-policy}")
	protected String csp;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// Enable CORS and disable CSRF
		http = http.cors().and().csrf().disable();

		http = http.headers().httpStrictTransportSecurity().includeSubDomains(true).maxAgeInSeconds(3600)//
				.and()//
				.frameOptions().sameOrigin() //
				.contentTypeOptions().and()//
				.contentSecurityPolicy(csp).and()//
				.referrerPolicy(ReferrerPolicy.ORIGIN).and()//
				.and();

		// Set session management to stateless
		http = http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and();

		// Set unauthorized requests exception handler
		http = http.exceptionHandling().authenticationEntryPoint((request, response, ex) -> {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
		}).and();

		// Set permissions on endpoints
		http.authorizeRequests()
				// Our public endpoints
				.antMatchers("/hello/guest").permitAll()
				// Our private endpoints
				.anyRequest().authenticated();

		// Add custom filters
		http.addFilterBefore(authFilter1, UsernamePasswordAuthenticationFilter.class);
		http.addFilterBefore(authFilter2, UsernamePasswordAuthenticationFilter.class);
	}

	/**
	 * DO NOT DELETE ME, required to skip the automatic init of
	 * UserDetailsServiceAutoConfiguration, see
	 * <https://stackoverflow.com/a/57365595/4832207>
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder authManager) throws Exception {
	}

	/**
	 * DO NOT DELETE ME, required to skip the automatic init of
	 * UserDetailsServiceAutoConfiguration, see
	 * <https://stackoverflow.com/a/57365595/4832207>
	 */
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource(
			@Value("${security.http.cors.allowed-origins}") List<String> allowedOrigins,
			@Value("${security.http.cors.allowed-methods}") List<String> allowedMethods) {
		log.info("CORS, allowed origins: {}", allowedOrigins);
		log.info("CORS, allowed methods: {}", allowedMethods);
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(allowedOrigins);
		configuration.setAllowedMethods(allowedMethods);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}