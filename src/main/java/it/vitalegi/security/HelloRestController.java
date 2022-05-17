package it.vitalegi.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("hello")
public class HelloRestController {

	Logger log = LoggerFactory.getLogger(this.getClass());

	@GetMapping("user")
	public String helloUser() {
		Authentication user = SecurityContextHolder.getContext().getAuthentication();
		return "Hello user: " + user;
	}

	@GetMapping("guest")
	public String helloGuest() {
		return "Hello guest";
	}

	@GetMapping("admin")
	public String helloAdmin() {
		return "Hello Admin";
	}

}