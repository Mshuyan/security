package com.spring4all.config;

import com.spring4all.filter.github.GitHubAuthenticationFilter;
import com.spring4all.filter.github.GitHubAuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/user/**").hasRole("USER")
                .and()
                .formLogin().loginPage("/login").defaultSuccessUrl("/user")
                .and()
                .logout().logoutUrl("/logout").logoutSuccessUrl("/login");

        // 在 UsernamePasswordAuthenticationFilter 前添加 GitHubAuthenticationFilter
        http.addFilterAt(gitHubAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    /**
     * 自定义 github登录 过滤器
     */
    private GitHubAuthenticationFilter gitHubAuthenticationFilter(){
        // 创建 GitHubAuthenticationFilter 对象，并指定拦截的 uri
        GitHubAuthenticationFilter authenticationFilter = new GitHubAuthenticationFilter("/login/github");
        // 创建 SimpleUrlAuthenticationSuccessHandler 对象，并配置验证成功好后跳转地址
        SimpleUrlAuthenticationSuccessHandler successHandler = new SimpleUrlAuthenticationSuccessHandler();
        successHandler.setAlwaysUseDefaultTargetUrl(true);
        successHandler.setDefaultTargetUrl("/user");
        // 配置 AuthenticationManager 和 AuthenticationSuccessHandler
        authenticationFilter.setAuthenticationManager(new GitHubAuthenticationManager());
        authenticationFilter.setAuthenticationSuccessHandler(successHandler);
        return authenticationFilter;
    }
}
