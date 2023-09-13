package com.SpringSecurity.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
   @Bean
	public UserDetailsService userDetailsService() {
	UserDetails user=User.withUsername("user").password(passwordEncorder().encode("123456")).roles("USER").build();
	UserDetails admin=User.withUsername("admin").password(passwordEncorder().encode("123456")).roles("ADMIN").build();
	return new InMemoryUserDetailsManager(user,admin);
		
		
	}
	@Bean
	public PasswordEncoder passwordEncorder() {
		return new BCryptPasswordEncoder();
	}
	
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		http.csrf().disable().authorizeHttpRequests().anyRequest().authenticated().and().formLogin();
		return http.build();
	}
	
}
