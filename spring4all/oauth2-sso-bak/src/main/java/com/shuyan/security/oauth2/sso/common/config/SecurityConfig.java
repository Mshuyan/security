package com.shuyan.security.oauth2.sso.common.config;

import com.shuyan.security.oauth2.sso.common.handler.CustomizeAccessDeniedHandler;
import com.shuyan.security.oauth2.sso.common.handler.CustomizeAuthenticationEntryPoint;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author will
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests().anyRequest().authenticated()
                .and().exceptionHandling()
                .accessDeniedHandler(new CustomizeAccessDeniedHandler())
                .authenticationEntryPoint(new CustomizeAuthenticationEntryPoint())
                .and().oauth2Login();
    }
}
