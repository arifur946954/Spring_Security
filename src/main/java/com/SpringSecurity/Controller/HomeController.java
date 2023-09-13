package com.SpringSecurity.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {
	
	@RequestMapping("/home")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public String home() {
		return "home";
	}
	@RequestMapping("/about")
	@PreAuthorize("hasAuthority('ROLE_USER')")
	public String about() {
		return "about";
	}

}
