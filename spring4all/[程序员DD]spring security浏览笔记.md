# [程序员DD]spring security浏览笔记

> 资料地址：
>
> + [Spring Security(一)--Architecture Overview](http://blog.didispace.com/xjf-spring-security-1/)及其前后相关`securoty`相关博客

## Architecture Overview

+ SecurityContextHolder

  + 用于存储安全上下文

    > 当前操作的用户是谁，该用户是否已经被认证，他拥有哪些角色权限…

  + 默认使用`ThreadLocal` 策略来存储认证信息

  + 通过SecurityContextHolder获取用户信息示例

    > 因为与线程绑定，所以在该线程中可以随时获取用户信息

    ```java
    Object principal = 
        //获取认证信息
        SecurityContextHolder.getContext().getAuthentication()
        //获取身份信息
        .getPrincipal();
    //UserDetails：用于封装身份信息的接口
    if (principal instanceof UserDetails) {
    String username = ((UserDetails)principal).getUsername();
    } else {
    String username = principal.toString();
    }
    ```

+ Authentication

  + 继承自`Principal`接口

  + 接口源码

    ```java
    public interface Authentication extends Principal, Serializable {
        // 获取权限信息列表
        Collection<? extends GrantedAuthority> getAuthorities();
    	// 获取用户输入的密码，认证成功后会被移除
        Object getCredentials();
    	// 更多细节，如访问者ip、sessionId等
        Object getDetails();
    	// 获取身份信息，大部分情况下返回的是UserDetail接口的实现类
        Object getPrincipal();
    	
        boolean isAuthenticated();
    
        void setAuthenticated(boolean var1) throws IllegalArgumentException;
    }
    ```

+ 身份验证流程

  +  用户名和密码被过滤器获取到，封装成`Authentication`,通常情况下是`UsernamePasswordAuthenticationToken`这个实现类。
  +  `AuthenticationManager` 身份管理器负责验证这个`Authentication`
  + 认证成功后，`AuthenticationManager`身份管理器返回一个被填充满了信息的（包括上面提到的权限信息，身份信息，细节信息，但密码通常会被移除）`Authentication`实例。
  + `SecurityContextHolder`安全上下文容器将第3步填充了信息的`Authentication`，通过SecurityContextHolder.getContext().setAuthentication(…)方法，设置到其中。

+ AuthenticationManager

  `AuthenticationManager`是1个接口，他有1个实现类`ProviderManager`，`ProviderManager`内部维护了1个`List<AuthenticationProvider>`列表，用来存放多种认证方式。使用`AuthenticationManager`认证时，就会使用`ProviderManager`内`List<AuthenticationProvider>`列表中的每种认证方式依次进行认证。

+ DaoAuthenticationProvider

  > 他是`AuthenticationProvider`接口最常用的实现类，用于从数据库中获取用户信息进行认证

  + 实现类内容

    该内中有2个对象：

    + PasswordEncoder

      > 用于对密码进行加密

    + UserDetailsService

      > 用于从数据库中查找用户信息

    该类中有3个方法：

    + `retrieveUser`

      + 功能：

        使用该类中的`UserDetailsService`对象，通过用户名从数据库中获取该用户的信息

      + 参数

        + username
          + 类型：String
          + 功能：用户名
        + authentication
          + 类型：UsernamePasswordAuthenticationToken
          + 功能：提交的用户名密码，用于抛出异常信息

      + 返回值

        + 类型：UserDetails
        + 功能：从数据库中获取到的用户信息

      + 说明

        该方法是实现其父类`AbstractUserDetailsAuthenticationProvider`中的抽象方法

    + `additionalAuthenticationChecks`

      + 功能：

        验证身份

      + 参数

        + userDetails
          + 类型：UserDetails
          + 功能：使用`retrieveUser`方法从数据库中获取到的用户信息
        + authentication
          + 类型：UsernamePasswordAuthenticationToken
          + 说明：提交上来的用户名密码

      + 说明

        该方法是实现其父类`AbstractUserDetailsAuthenticationProvider`中的抽象方法

    + authenticate

      + 说明

        该方法是其父类`AbstractUserDetailsAuthenticationProvider`中的方法

      + 功能

        调用`retrieveUser`和`additionalAuthenticationChecks`方法进行身份认证

      + 参数

        + authentication
          + 类型：Authentication
          + 说明：提交上来的用户名密码

      + 返回值

        从数据库中获取的用户信息

## Guides

> + 参见[helloworld](./helloworld) 
>
> + 该例程是基于springboot使用security，其他方式使用sucurity参见[spring官网](https://docs.spring.io/spring-security/site/docs/5.0.8.RELEASE/reference/htmlsingle/#what-is-acegi-security)中的demo

+ springboot中使用security步骤

  + 引入依赖

    ```xml
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    ```

  + 加入`security`配置类

    ```java
    @Configuration
    @EnableWebSecurity
    public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // 配置访问url需要的用户或权限
            http.authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
            // and()返回HttpSecurity本身
            .and().formLogin()
                .loginPage("/login").permitAll()
            .and().logout()
                .permitAll();
        }
    
        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    
            auth
                .inMemoryAuthentication()
                .withUser("user").password(encoder.encode("password")).roles("USER")
                .and()
                .passwordEncoder(encoder);
        }
    }
    ```

## 核心配置解读

### @EnableWebSecurity

+ 源码

  ```java
  @Import({ WebSecurityConfiguration.class,
  		SpringWebMvcImportSelector.class })
  @EnableGlobalAuthentication
  ```

  + `@Import`

    激活注解中包含的2个配置类

    + WebSecurityConfiguration：用于配置web安全
    + SpringWebMvcImportSelector：判断当前环境是否包含springMVC

  + `@EnableGlobalAuthentication`

    源码

    ```java
    @Import(AuthenticationConfiguration.class)
    ```

    激活`AuthenticationConfiguration`配置类，用户身份认证

+ WebSecurityConfiguration

  该配置类中注册了1个非常重要的Bean：**springSecurityFilterChain**

  这个Bean是security的核心过滤器，是整个认证的入口，该过滤器最终将请求交给`DelegatingFilterProxy`去处理

+ AuthenticationConfiguration

  用于生成`AuthenticationManager`，就是[Architecture Overview](#Architecture Overview)中的身份认证器

### WebSecurityConfigurerAdapter

> 该类是security配置的适配器，重写该类中的方法可以进行自定义配置
>
> 通常需要重写的方法：

+ configure(HttpSecurity http)

  > 用于配置每个URL需要哪些角色或者拥有哪些权限才能访问
  >
  > 更多细节参见[初步理解Spring Security并实践](https://www.jianshu.com/p/e6655328b211) 
  >
  > httpBasic参见[springSecurity 之 http Basic认证](https://blog.csdn.net/u012373815/article/details/56832167) 

+ configure(AuthenticationManagerBuilder auth)

  + `AuthenticationManagerBuilder`是用于生成`AuthenticationManager`的，通过配置`AuthenticationManagerBuilder`来配置`AuthenticationManager`
  + 该配置只对当前`WebSecurityConfigurerAdapter`有效

+ configureGlobal(AuthenticationManagerBuilder auth)

  + 作用同`configure(AuthenticationManagerBuilder auth)`
  + 对整个应用中所有`WebSecurityConfigurerAdapter`有效；当整个应用只有1个`WebSecurityConfigurerAdapter`时，这两者几乎没区别

## 核心过滤器源码分析



