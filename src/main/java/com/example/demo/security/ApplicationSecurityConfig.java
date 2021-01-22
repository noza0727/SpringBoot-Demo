package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.demo.security.ApplicationEnumRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http                        // new configuration
                .authorizeRequests()// authorize request
                .antMatchers("/", "index", "/css/*", "/js/*")  // permit entrance to main page
                .permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name()) //only student can access, no admin
                                                                        //though student can access another student yet
                .anyRequest()     //any request must be authenticated
                .authenticated()  // user must specify username and password
                .and()
                .httpBasic();  //mechanism enforcing authenticity of the client by using basic authentication, sign in pop up
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService(){
        UserDetails user3 =  User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password")) //.password("password")-no password encoder so it does not work
                .roles(STUDENT.name())  //uses as ROLE_STUDENT
                .build();
        UserDetails adminUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMIN.name())
                .build();

        return new InMemoryUserDetailsManager(
                user3,
                adminUser
        );
    }
}
