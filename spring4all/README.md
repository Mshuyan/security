# security

>  security学习
>
>  本次基于springboot学习
>
>  + 参考资料
>
>    [Spring Security 从入门到进阶系列教程](http://www.spring4all.com/article/428) 
>
>  + 前置知识：
>
>    [[程序员DD]spring security浏览笔记](./[程序员DD]spring security浏览笔记.md) ，这里讲解了`hello world`示例程序，本文不再讲解

## 基于数据库使用security

> demo参见[security-jdbc](./security-jdbc) 

### demo讲解

+ 建表（`user表`）

  > 字段如下：

  + id：int，自增主键，记录唯一标识
  + username：varchar(50)，用户名
  + password：varchar(100)，密码
  + nick_name：varchar(50)，昵称
  + roles：varchar(255)，权限列表

  > **注意**
  >
  > 1. password字段长度不要太小，密码加密后比较长
  > 2. 这里为了方便将权限放在用户表的1个字段中，实际开发中应该需要中间表

+ 集成mybatis，创建1个`user表`的`service`，提供`getByUsername`方法

+ 编写1个实现`UserDetailsService`接口的类

  > 该类用于从数据库中查找用户正确的密码、权限等信息，用以身份认真

  ```java
  /**
   * @author will
   * 实现 UserDetailsService 接口，重写 loadUserByUsername 方法
   */
  @Service
  public class CustomUserDetailServiceImpl implements UserDetailsService {
  
      /**
       * 注入自己实现的 UserService
       */
      private final UserService userServiceImpl;
  
      @Autowired
      public CustomUserDetailServiceImpl(UserService userServiceImpl) {
          this.userServiceImpl = userServiceImpl;
      }
  
      /**
       * 根据用户名查询该用户的密码、权限等信息
       * @param username 需要验证的用户名
       * @return 数据库中查到的用户信息
       * @throws UsernameNotFoundException 未找到用户异常
       */
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
          UserDto userDto = userServiceImpl.getByUsername(username);
          if(userDto == null){
              throw new UsernameNotFoundException("用户不存在！");
          }
          // 权限转换
          List<SimpleGrantedAuthority> simpleGrantedAuthorities = createAuthorities(userDto.getRoles());
          // 将查询结果封装到指定的对象中并返回
          return new User(userDto.getUsername(), userDto.getPassword(), simpleGrantedAuthorities);
      }
  
      /**
       * 将权限字符串转换为List<SimpleGrantedAuthority>
       * @param roleStr 数据库中查到的权限字符串
       * @return 需要的权限集合
       */
      private List<SimpleGrantedAuthority> createAuthorities(String roleStr){
          String[] roles = roleStr.split(",");
          List<SimpleGrantedAuthority> simpleGrantedAuthorities = new ArrayList<>();
          for (String role : roles) {
              simpleGrantedAuthorities.add(new SimpleGrantedAuthority(role));
          }
          return simpleGrantedAuthorities;
      }
  }
  ```

+ 将上面实现的`CustomUserDetailServiceImpl`在`security配置类`中配置到`AuthenticationManagerBuilder`中

  ```java
  @Configuration
  @EnableWebSecurity
  public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
      @Autowired
      private UserDetailsService customUserDetailServiceImpl;
  
      // 此处省略其他配置
      
      @Autowired
      public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
          auth.userDetailsService(customUserDetailServiceImpl);
      }
  }
  ```

+ 注册功能

  > 上面的配置是基于数据库进行验证，注册功能就需要自己实现了
  >
  > + 自己实现注册功能的post请求接口，对参数进行校验，并调用service层
  > + 在service层中对数据进行处理并存库

  ```java
  @Service
  public class UserServiceImpl implements UserService {
      @Autowired
      private UserMapper userMapper;
      @Autowired
      private PasswordEncoder passwordEncoder;
  
      @Override
      public Boolean addUser(UserDto user) {
          if(userMapper.getByUsername(user.getUsername()) != null){
              return false;
          }
          user.setPassword(passwordEncoder.encode(user.getPassword()));
          // RoleConstant.ROLE_USER = "ROLE_USER"
          user.setRoles(RoleConstant.ROLE_USER);
          userMapper.addUser(user);
          return true;
      }
  }
  ```

## CSRF

- 什么是CSRF攻击

  > 资料参见：[浅谈CSRF攻击方式](https://www.cnblogs.com/hyddd/archive/2009/04/09/1432744.html) 

  - CSRF攻击全称`跨站请求攻击`

    当用户同时打开两个网站的网页A、B；A网页登录后产生cookie存放于浏览器；此时操作B网页，如果网页B是来自于1个黑客的网站，该网页上包含了请求网页A的代码，则用户在网页B上的操作很有可能触发这个发往网页A的服务器的请求，此时浏览器会自动携带前面产生的cookie，此时网页B就可以伪装成用户在网站A上进行操作了

  - 防范措施

    网页B只能向网站A发送请求，携带cookie是浏览器携带的，网页B本身并不能拿到网页A的coockie，基于这点，可以在网页A的表单中添加1个隐藏的参数，该参数中的值就是将cookie中的值，在服务端对该值进行验证。

- `spring security`中针对`CSRF`攻击的处理

  + 请求方式

    security默认仅对`GET`、`HEAD`、`TRACE`、`OPTIONS`不进行`csrf`攻击验证，其他的请求均会进行验证

  + 处理方式

    > 参见：[spring security的跨域保护(CSRF Protection)](https://www.jianshu.com/p/672b6390c25f) 

    security会在后端生成1个用于校验`csrf`攻击的`cookie`字符串，存储在session中，然后将该字符串以**直接设置到页面**或**设置到request的cookie中（cookie名称：XSRF-TOKEN）**的方式返回给前端，下次请求时会校验**表单参数（_csrf）**或**请求头（X-XSRF-TOKEN）**的值是否与session保存的值相同，来防止csrf攻击。

  + 默认实现方式

    默认情况下，security在生成名为`XSRF-TOKEN`的cookie时，进行了两种处理：

    + 通过`request.setAttribute`方法设置到request的属性中，这样jsp页面就可以轻松的获得这个值；
    + 将名为`XSRF-TOKEN`的cookie的`cookieHttpOnly`属性设置为`true`，以防止XSS攻击

    security自动生成的登录页面就是通过`request.getAttribute`获取这个属性值并设置到form中，然后将页面返回给前端的。

    但是通过`getAttribute`获取该值有1个限制，必须使用jsp，而对于前后端分离来说，并不适用。

- 从cookie中获取`XSRF-TOKEN`

  由于security的名为`XSRF-TOKEN`的cookie的`cookieHttpOnly`属性默认为`true`，所以需要先在后端将该属性设置为`false`，js才能从cookie中获取`XSRF-TOKEN`

  后端配置代码如下：

  ```java
  protected void configure(HttpSecurity http) throws Exception {
  	http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
  }
  ```

  然后就可以通过如下任意一种方式通过csrf验证了

  + 通过form表单处理

    将从cookie中获取的`XSRF-TOKEN`的值设置到from表单中，该值对应的参数名称为`_csrf`

  + 通过请求头处理

    将从cookie中获取的`XSRF-TOKEN`的值设置到请求头中，该值对应的请求头名称为`X-XSRF-TOKEN`

- `CookieCsrfTokenRepository`

  > 该实现类是通过cookie方式防止csrf攻击，方案是将浏览器发来的请求中的表单参数或请求头，与自己下发的cookie进行比对，相等则通过

## PasswordEncoder

> 该接口是用于密码加密的，每一个实现类都是1种加密算法

使用方法：

> 在security配置类中注册1个`PasswordEncoder`的Bean

```java
@Bean
public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
}
```

此时，security就会使用这个`PasswordEncoder`对密码进行校验

> 在注册时，使用这个`PasswordEncoder`对密码进行加密后存储在数据库

```java
@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserMapper userMapper;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Boolean addUser(UserDto user) {
        if(userMapper.getByUsername(user.getUsername()) != null){
            return false;
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        // RoleConstant.ROLE_USER = "ROLE_USER"
        user.setRoles(RoleConstant.ROLE_USER);
        userMapper.addUser(user);
        return true;
    }
}
```

> 官方推荐加密算法`BCryptPasswordEncoder`

### salt

> 在security5.0版本以后，去除了`SaltSource`这个类，用户不需要关心盐，Security会自动对密码加盐

## 过滤器

### 默认过滤器

+ 默认过滤器顺序

  > 执行顺序由上而下

  | 别名                             | 类名称                                                | Namespace Element or Attribute                               |
  | -------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------ |
  | CHANNEL_FILTER                   | ChannelProcessingFilter                               | http/intercept-url[@requires](https://github.com/requires)-channel |
  | **SECURITY_CONTEXT_FILTER**      | **SecurityContextPersistenceFilter**                  | **http**                                                     |
  | CONCURRENT_SESSION_FILTER        | ConcurrentSessionFilter                               | session-management/concurrency-control                       |
  | HEADERS_FILTER                   | HeaderWriterFilter                                    | http/headers                                                 |
  | CSRF_FILTER                      | CsrfFilter                                            | http/csrf                                                    |
  | LOGOUT_FILTER                    | LogoutFilter                                          | http/logout                                                  |
  | X509_FILTER                      | X509AuthenticationFilter                              | http/x509                                                    |
  | PRE_AUTH_FILTER                  | AbstractPreAuthenticatedProcessingFilter( Subclasses) | N/A                                                          |
  | CAS_FILTER                       | CasAuthenticationFilter                               | N/A                                                          |
  | **FORM_LOGIN_FILTER**            | **UsernamePasswordAuthenticationFilter**              | **http/form-login**                                          |
  | BASIC_AUTH_FILTER                | BasicAuthenticationFilter                             | http/http-basic                                              |
  | SERVLET_API_SUPPORT_FILTER       | SecurityContextHolderAwareRequestFilter               | http/[@servlet](https://github.com/servlet)-api-provision    |
  | JAAS_API_SUPPORT_FILTER          | JaasApiIntegrationFilter                              | http/[@jaas](https://github.com/jaas)-api-provision          |
  | REMEMBER_ME_FILTER               | RememberMeAuthenticationFilter                        | http/remember-me                                             |
  | **ANONYMOUS_FILTER**             | **AnonymousAuthenticationFilter**                     | **http/anonymous**                                           |
  | SESSION_MANAGEMENT_FILTER        | SessionManagementFilter                               | session-management                                           |
  | **EXCEPTION_TRANSLATION_FILTER** | **ExceptionTranslationFilter**                        | **http**                                                     |
  | **FILTER_SECURITY_INTERCEPTOR**  | **FilterSecurityInterceptor**                         | **http**                                                     |
  | SWITCH_USER_FILTER               | SwitchUserFilter                                      | N/A                                                          |

+ 核心过滤器源码分析

  > 上面加粗的5个过滤器是核心过滤器
  >
  > 核心过滤器的源码分析参见[核心过滤器源码分析](http://www.spring4all.com/article/447) 

### 自定义过滤器

+ 定义过滤器

  > 自定义过滤器建议继承`GenericFilterBean`

  ```java
  public class BeforeLoginFilter extends GenericFilterBean {
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
          System.out.println("This is a filter before UsernamePasswordAuthenticationFilter.");
          // 继续调用 Filter 链
          filterChain.doFilter(servletRequest, servletResponse);
      }
  }
  ```

+ 配置自定义filter在security过滤器链中位置

  > 在security配置类中，通过配置`HttpSecurity`来配置

  + 方法

    > HttpSecurity对象有4个方法用于配置自定义Filter的位置

    + addFilterBefore

      功能：将自定义filter配置在指定filter之前

      参数：

      ​	Filter filter：自定义的filter对象

      ​	 Class<? extends Filter> afterFilter：相对于哪个默认filter

    + addFilterAfter

      功能：将自定义filter配置在指定filter之后

      参数：与`addFilterBefore`相同

    + addFilterAt

      功能：在 指定Filter 相同位置添加 filter， 此 filter 不覆盖 filter，经测试自定义filter会在原有filter之前执行

      参数：与`addFilterBefore`相同

  + demo

    ```java
    protected void configure(HttpSecurity http) throws Exception {
            http.addFilterBefore(new BeforeLoginFilter(),UsernamePasswordAuthenticationFilter.class);
        }
    ```

### 自定义过滤器实现授权登录

> 代码参见[security-oauth2-github](./security-oauth2-github) 
>
> 本例程使用的是github的授权登录
>
> OAUTH2原理参见[OAuth2](#OAuth2) 

+ 请求code

  ```html
  <a href="https://github.com/login/oauth/authorize?client_id=4ffc7077a0308557b0c1&state=test&scope=user" class="btn btn-primary btn-block">GitHub登录</a>
  ```

+ 创建自定义过滤器

  ```java
  public class GitHubAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
  
      private final static String CODE = "code";
  
      private final static String CLIENT_ID = "4ffc7077a0308557b0c1";
  
      private final static String ACCESS_TOKEN_URI = "https://github.com/login/oauth/access_token";
  
      private Map<String,String> postParamMap = new HashMap<>();
      {
          postParamMap.put("client_id",CLIENT_ID);
          postParamMap.put("client_secret","9cdfc9cc3e1aafcb3262e5f31b58d136aca991fa");
      }
  
      /**
       * 构造方法中指定拦截的uri和请求方式，拦截的uri就是github上创建应用时指定的redirect_uri
       * @param defaultFilterProcessesUrl 拦截的uri
       */
      public GitHubAuthenticationFilter(String defaultFilterProcessesUrl) {
          super(new AntPathRequestMatcher(defaultFilterProcessesUrl, "GET"));
      }
  
      /**
       * 从拦截到的请求中获取请求参数code
       * 使用在github上创建应用时产生的client_id、client_secret和拦截到的code从认证服务器获取token
       * 将token交给{@link AuthenticationManager}进行身份认证并返回该用户的{@link Authentication}对象
       * @param request 拦截到的请求的request对象
       * @param response 拦截到的请求的response对象
       * @return 包含用户信息的 Authentication 对象
       * @throws AuthenticationException 身份认证失败异常
       * @throws IOException 与认证服务器通信异常
       */
      @Override
      public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
          String code = request.getParameter(CODE);
          postParamMap.put("code",code);
          String gitHubToken = this.getToken(postParamMap);
          if (gitHubToken != null){
              UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(gitHubToken, null);
              // 返回验证结果
              return this.getAuthenticationManager().authenticate(authRequest);
          }
          return null;
      }
  
      /**
       * 使用code、client_id、client_secret从认证服务器获取token
       * @param map 请求参数
       * @return token
       * @throws IOException 请求失败异常
       */
      private String getToken(Map<String,String> map) throws IOException{
          Connection conn = Jsoup.connect(ACCESS_TOKEN_URI).ignoreContentType(true);
          if(map!=null){
              for (Map.Entry<String, String> entry : map.entrySet()) {
                  conn.data(entry.getKey(), entry.getValue());
              }
          }
          Document doc = conn.post();
          String tokenResult = doc.text();
          String[] results = tokenResult.split("&");
          if (results.length == 3){
              return results[0].replace("access_token=", "");
          }
          return null;
      }
  }
  ```

+ 创建自定义`AuthenticationManager`

  ```java
  public class GitHubAuthenticationManager implements AuthenticationManager {
      /**
       * 默认角色列表
       */
      private static final List<GrantedAuthority> AUTHORITIES = new ArrayList<>();
      static {
          AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_USER"));
      }
      /**
       * 获取 GitHub 用户信息的 API 地址
       */
      private final static String USER_INFO_URI = "https://api.github.com/user?access_token=";
  
      /**
       * 实现 authenticate 方法，用于身份认证
       * @param auth 提交上来的用户信息，这里传入的是 token
       * @return 数据库中查到的用户信息，这里为从github上获取的用户信息
       * @throws AuthenticationException 传入的用户信息参数错误
       */
      @Override
      public Authentication authenticate(Authentication auth) throws AuthenticationException {
          // 查看源码可知，这里获取的是前面传入的token
          if (auth.getName() != null) {
              GitHubUser user = getUserInfo(auth.getName());
              return new UsernamePasswordAuthenticationToken(user,
                      null, AUTHORITIES);
          }
          throw new BadCredentialsException("Bad Credentials");
      }
  
      /**
       * 使用token从github获取用户信息
       * @param accessToken token
       * @return 用户信息实体类
       */
      private GitHubUser getUserInfo(String accessToken) {
          try {
              Connection conn = Jsoup.connect(USER_INFO_URI + accessToken).ignoreContentType(true);
              Document doc = conn.get();
              String resultText = doc.text();
              JSONObject json = JSON.parseObject(resultText);
  
              GitHubUser user = new GitHubUser();
              user.setUsername(json.getString("login"));
              user.setUserId(json.getLong("id"));
              user.setAvatarUrl(json.getString("avatar_url"));
              user.setHtmlUrl(json.getString("html_url"));
              user.setNickName(json.getString("name"));
              user.setBio(json.getString("bio"));
  
              return user;
          }catch (IOException e){
              return null;
          }
      }
  }
  ```

+ 配置过滤器

  ```java
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
  ```

## CORS

### 配置

> 未使用`security`之前配置跨域，可以使用如下方法进行配置

```java
@Bean
@Order(0)
public FilterRegistrationBean corsFilter() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(false);
    // 设置你要允许的网站域名，如果全允许则设为 *
    config.addAllowedOrigin("*");
    // 如果要限制 HEADER 或 METHOD 请自行更改
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    config.addExposedHeader("Content-Disposition");
    source.registerCorsConfiguration("/**", config);
    return new FilterRegistrationBean<>(new CorsFilter(source));
}
```

> 使用`security`之后，因为`login`接口是由`security`提供的，所以上述方法无法对`login`接口提供跨域支持，此时需要使用`security`提供的跨域方法

在secirity配置类中：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.exceptionHandling()
        .accessDeniedHandler(new CustomizeAccessDeniedHandler())
        .authenticationEntryPoint(new CustomizeAuthenticationEntryPoint())
        .and().authorizeRequests()
        .antMatchers("/**.html").permitAll()
        // 在这里配置cors
        .and().cors().configurationSource(corsConfigurationSource())
        .and().csrf().disable();
    http.addFilterAt(jwtLoginFilter(), UsernamePasswordAuthenticationFilter.class);
    http.addFilter(jwtAuthenticationFilter());
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
}

private UrlBasedCorsConfigurationSource corsConfigurationSource(){
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(false);
    // 设置你要允许的网站域名，如果全允许则设为 *
    // 只能设为 * 或具体的域名，不可以设置模糊的域名
    config.addAllowedOrigin("*");
    // 如果要限制 HEADER 或 METHOD 请自行更改
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    /* 非跨域请求时，服务端返回自定义的响应头前端能够获取到
     * 跨域请求中前端获取不到，则服务端需要通过配置ExposedHeader来将这些头暴露出去
     * 让前端可以获取到
     */
    config.addExposedHeader("Content-Disposition");
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

### 同源

> security的cors中，如果`发起请求的页面`与`请求的接口`本身就是同源，则不会返回cors相关响应头

在一次请求中，如果`Host`与`Origin`请求头同源，则不会返回cors相关响应头

参见`org.springframework.web.util.isSameOrigin`方法

#### 采坑记录

+ 场景

  ​	后端开发完成后，将代码打包放在服务器上运行(端口8080)，并配置了nginx，nginx将请求转发给`localhost:8080`

  ​	前端在开发人员本机开发，请求服务器端数据进行调试，其本机测试地址为`localhost:8080`

+ 问题

  ​	当前端向后端发请求时，报错说跨域出错了

+ 分析

  ​	前端本机发给服务器的请求：`Host`:`www.xxxx.com`，`Origin`:`localhost:8080`

  ​	经nginx代理后：`Host`:`localhost:8080`，`Origin`:`localhost:8080`

  ​	此时cors就会判定该请求为同源请求，不返回cors相关响应头

+ 解决方案

  在nginx中配置，在dialing过程中，不替换`Host`请求头的值

  ```shell
  proxy_set_header Host $host;
  ```

## 前后端分离项目中使用security

> 参见[Spring Security 访问控制-实现 RESTful API](https://blog.csdn.net/pomer_huang/article/details/77902392?utm_source=blogxgwz3) 

重写如下处理器即可：

+ http.exceptionHandling().accessDeniedHandler()
+ http.exceptionHandling().authenticationEntryPoint()
+ http.formLogin().successHandler()
+ http.formLogin().failureHandler()
+ http.logout().logoutSuccessHandler()

> demo参见[产业地图](https://github.com/Mshuyan/industry-map) 

## 整合JWT

> 参见：[Spring Security 初识（五）–spring security 和jwt整合](https://blog.csdn.net/itguangit/article/details/78960127) 

security整合JWT是通过filter实现的，这里需要实现2个过滤器：登录过滤器，验证过滤器

demo参见[产业地图](https://github.com/Mshuyan/industry-map) 

## 控制session

> 参见[spring security控制session](https://blog.csdn.net/neweastsun/article/details/79371175) 

## 注解控制权限

> 参见：
>
> + [Spring Security（16）——基于表达式的权限控制](https://www.cnblogs.com/fenglan/p/5913463.html) 
> + [Spring Security（17）——基于方法的权限控制](https://www.cnblogs.com/fenglan/p/5913481.html) 
> + [Spring Security 入门详解](https://www.cnblogs.com/jaylon/p/4905769.html) 

### 启用注解控制权限

需要在security配置类上加上如下注解

```java
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
```

### 注解

#### @Secured与@RolesAllowed

+ `@RolesAllowed`

  JSR250标准提供的注解，参数字符串不具备`SpEL`特性，是具体的权限

+ `@Secured`

  与`@RolesAllowed`相同，是spring提供的

#### 方法调用前后注解

> 以下注解支持SpEL表达式，security支持的表达式如下：
>
> | 安全表达式                | 计算结果                                 |
> | ------------------------- | ---------------------------------------- |
> | authentication            | 用户认证对象                             |
> | denyAll                   | 结果始终为false                          |
> | hasAnyRole(list of roles) | 如果用户被授权指定的任意权限，结果为true |
> | hasRole(role)             | 如果用户被授予了指定的权限，结果 为true  |
> | hasIpAddress(IP Adress)   | 用户地址                                 |
> | isAnonymous()             | 是否为匿名用户                           |
> | isAuthenticated()         | 不是匿名用户                             |
> | isFullyAuthenticated      | 不是匿名也不是remember-me认证            |
> | isRemberMe()              | remember-me认证                          |
> | permitAll                 | 始终true                                 |
> | principal                 | 用户主要信息对象                         |

+ `@PreAuthorize`

  > 在方法调用前，基于表达式计算结果来限制方法访问
  >
  > 例：@PreAuthorize("hasRole('ROLE_ADMIN')")

+ `@PostAuthorize`

  > 允许方法调用，但是如果表达式结果为fasle则抛出异常

  例

  ```java
  @PostAuthorize("returnObject.id%2==0")
  public User find(int id) {
      User user = new User();
      user.setId(id);
      return user;
  }
  ```

  ​	上面这一段代码表示将在方法find()调用完成后进行权限检查，如果返回值的id是偶数则表示校验通过，否则表示校验失败，将抛出AccessDeniedException。       需要注意的是@PostAuthorize是在方法调用完成后进行权限检查，它不能控制方法是否能被调用，只能在方法调用完成后检查权限决定是否要抛出AccessDeniedException

+ `@PostFilter`

  > 允许方法调用，但必须按表达式过滤方法结果
  >
  > Spring Security将移除使对应表达式的结果为false的元素。

  ```java
  @PostFilter("filterObject.id%2==0")
  public List<User> findAll() {
      List<User> userList = new ArrayList<User>();
      User user;
      for (int i=0; i<10; i++) {
          user = new User();
          user.setId(i);
          userList.add(user);
      }
      return userList;
  }
  ```

+ `@PreFilter`

  > 允许方法调用，但必须在进入方法前过滤输入值
  >
  > Spring Security将移除使对应表达式的结果为false的元素。

  ```java
  @PreFilter(filterTarget="ids", value="filterObject%2==0")
  public void delete(List<Integer> ids, List<String> usernames) {
      ...
  }
  ```


