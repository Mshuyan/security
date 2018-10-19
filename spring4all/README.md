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

### 角色

security中没有默认的角色，每一个不同的字符串都可以认为是1个角色名

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


## OAuth2

> OAuth2是用于第三方授权登录的开放网络标准
>
> [rfc6749](https://tools.ietf.org/html/rfc6749) 

### 角色

+ **Third-party application**：第三方应用程序，又称"客户端"（client）
+ **HTTP service**：HTTP服务提供商
+ **Authorization server**：HTTP服务提供商的认证服务器
+ **Resource server**：HTTP服务提供商的资源服务器
+ **Resource Owner**：资源所有者，又称"用户"
+ **User Agent**：用户代理，就是浏览器

### 授权模式

> OAuth 2.0定义了四种授权方式
>
> + 授权码模式
> + 密码模式
> + 客户端模式
> + 简化模式（不常用，这里不介绍）

#### 授权码模式

> 授权码模式（authorization code）是功能最完整、流程最严密的授权模式。也是qq、微信、github等大型网站使用的模式

![image-20181014191805691](assets/image-20181014191805691.png)   

+ A

  > `客户端`在返回登录页时，会将1个向`认证服务器`请求授权的GET请求链接包含在页面中一起返回
  >
  > 当`用户`点击该链接后，`浏览器`向`认证服务器`发送1个GET请求，目的是从`认证服务器`获取1个`code`

  参数：

  + response_type：表示授权类型，必选项，此处的值固定为`code`；

    > 部分`认证服务器`不要求该参数，具体参见对应`认证服务器`的使用说明

  + client_id：表示客户端的ID，必选项；

    > 在`服务提供商`上创建应用后获得

  + redirect_uri：表示重定向URI，可选项；

    > + 用户在认证服务器上通过认证后，认证服务器会生成1个`code`返回给客户端，该参数配置的就是将`code`返回给客户端服务器时需要的回调地址
    >
    > + 如果不配置该参数，默认使用在`服务提供商`上创建应用时配置的`redirect_uri`
    >
    >   如果指定该参数，则回调地址会使用指定的`redirect_uri`，但会指定的`redirect_uri`必须与创建应用时配置的`redirect_uri`相同或是配置的`redirect_uri`的子地址
    >
    >   如：创建应用时配置的是`www.bymyself.club/login/github`
    >
    >   则指定该参数时可以指定为`www.bymyself.club/login/github`或`www.bymyself.club/login/github/test`，但是不能配置为``www.bymyself.club/login/test`

  + scope：表示申请的权限范围，可选项

    > 该参数没有备选值，由`服务提供商`自行定义可接受哪些参数

  + state：可以指定任意值，认证服务器会原封不动地返回这个值。

    > 用于防止CSRF攻击，与前面讲到的`_csrf`参数是1个东西

+ B

  > `认证服务器`返回登录页面，让用户进行登录并授权

+ C

  > 用户填写他在`认证服务器`上的用户名密码进行登录并进行授权

+ D

  > + `认证服务器`返回1个重定向的响应
  >
  > + 该响应会携带用户登录`认证服务器`产生的cookie
  >
  > + 重定向地址为`${redirect_uri}?code=xxxxx&state=${state}`
  >   + redirect_uri：创建应用时或在A步中请求`认证服务器`时指定的`redirect_uri`
  >   + code：认证通过后返回的code，用于下一步客户端从`认证服务器`获取`token`
  >   + state：A步中请求`认证服务器`时指定的`state`被原封不动的返回
  >
  > + 浏览器接收到重定向响应后直接重定向到`${redirect_uri}?code=xxxxx&state=${state}`

+ E

  > 客户端使用接收到的`code`，创建应用时生成的`client_id`、`client_secret`请求认证服务器，来获取token

  参数：

  - grant_type：表示授权类型，必选项，此处的值固定为`authorization_code`；

    > 部分`认证服务器`不要求该参数，具体参见对应`认证服务器`的使用说明

  - code：上一步得到的`code`，必选项

  - redirect_uri：同A步中的`redirect_uri`，非必须

  - client_id：表示客户端的ID，必选项；

    > 在`服务提供商`上创建应用后获得

  - client_secret 表示客户端的ID对应的秘钥，必选项；

    > 在`服务提供商`上创建应用后获得

+ F

  > `认证服务器`返回token以及一些其他参数

+ G

  > 客户端将获得的token作为GET请求的参数或设置到请求头中，来向资源服务器获取资源
  >
  > 具体过程参见要使用的服务提供商的说明

+ H

  > 资源服务器返回资源

#### 密码模式

> 密码模式就是用户将自己位于`服务提供商`的`认证服务器`上的账号密码都交给客户端，由客户端自己去申请授权并拉取资源

#### 客户端模式

> 客户端模式其实与用户没有任何关系，客户端向认证服务器发送请求来验证自己的身份，通过验证后从资源服务器获取资源


