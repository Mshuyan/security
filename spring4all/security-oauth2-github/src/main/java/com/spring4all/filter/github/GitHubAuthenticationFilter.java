package com.spring4all.filter.github;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author will
 */
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
