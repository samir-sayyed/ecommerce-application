package com.example.demo.security;

import com.example.demo.constants.Constants;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class Configuration extends WebSecurityConfigurerAdapter {

    private UserServiceImpl userDetailsService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public Configuration(UserServiceImpl userDetailsService,
                         BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }





//
// http.cors().and().csrf().disable().authorizeRequests()
//     .antMatchers(HttpMethod.POST, Constants.SIGN_UP_URL).permitAll()
    @Override
    protected void configure(HttpSecurity http) throws Exception {


        http.cors().and().csrf().disable().authorizeRequests()
                .antMatchers(HttpMethod.POST, Constants.SIGN_UP_URL).permitAll()


                .anyRequest().authenticated()


                .and()

                .addFilter(new JWTFilter(authenticationManager()))

                .addFilter(new JWTVerficationFilter(authenticationManager()))


                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

//      .addFilter(new JWTFilter(authenticationManager()))
//
//            .addFilter(new JWTVerficationFilter(authenticationManager()))








    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }
}