package com.dogjaw.services.authentication;

import com.dogjaw.services.authentication.logging.AuthorizationLoggingIntercepter;
import com.dogjaw.services.authentication.tokens.AzureIdTokenProvider;
import com.dogjaw.services.authentication.tokens.AzureRequestEnhancer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.*;

/**
 * Created by Keith Hoopes on 2/1/2016.
 * Copyright Bear River Mutual 2016.
 */
@RestController
@Configuration
@EnableOAuth2Client
@EnableAuthorizationServer
@Order(6)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @SuppressWarnings("SpringJavaAutowiringInspection")
    @Autowired
    OAuth2ClientContext oauth2ClientContext;

    @RequestMapping({"/user", "/me", "/users"})
    public Map<String, String> user(Principal principal) {

        Map<String, String> map = new LinkedHashMap<>();
        map.put("name", principal.getName());
        return map;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/", "/login**", "/webjars/**").permitAll()
                .anyRequest().authenticated()
                .and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
                .and().logout().logoutSuccessUrl("/").permitAll()
                .and().csrf().csrfTokenRepository(csrfTokenRepository())
                .and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
                .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
        // @formatter:on
    }

    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration
            extends ResourceServerConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                    .antMatcher("/me")
                    .authorizeRequests().anyRequest().authenticated();
            // @formatter:on
        }
    }

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(
            OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    @Bean
    @ConfigurationProperties("github")
    ClientResources github() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("azure")
    ClientResources azure() {
        return new ClientResources();
    }

    private Filter ssoFilter() {

        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilter(azure(), "/login/azure"));
        filters.add(ssoFilter(github(), "/login/github"));
        filter.setFilters(filters);
        return filter;
    }

    private Filter ssoFilter(ClientResources client, String path) {


        OAuth2ProtectedResourceDetails clientResources = client.getClient();
        OAuth2RestTemplate azureTemplate = new OAuth2RestTemplate(
                clientResources,
                oauth2ClientContext
        );
        azureTemplate.setAccessTokenProvider(client.getAccessTokenProvider());
        azureTemplate.getInterceptors().add(new AuthorizationLoggingIntercepter());

        UserInfoTokenServices tokenServices = new UserInfoTokenServices(
                client.getResource().getUserInfoUri(),
                client.getClient().getClientId());

        JwtTokenStore jwtTokenStore = new JwtTokenStore(new JwtAccessTokenConverter());

//        DefaultTokenServices tokenServices = new DefaultTokenServices();
//        tokenServices.setTokenStore(jwtTokenStore);

//        RemoteTokenServices tokenServices = new RemoteTokenServices();

//        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
//        Map<String, ClientDetails> detailsStore = new HashMap<>();
//        detailsStore.put(clientResources.getClientId(),clientResources)
//        clientDetailsService.setClientDetailsStore();
//        tokenServices.setClientDetailsService(clientDetailsService);
//
//        tokenServices.setClientSecret(clientResources.getClientSecret());
//        tokenServices.setTokenName(clientResources.getTokenName());
//        tokenServices.setCheckTokenEndpointUrl(clientResources.getAccessTokenUri());

        tokenServices.setRestTemplate(azureTemplate);

        OAuth2ClientAuthenticationProcessingFilter azureFilter = new OAuth2ClientAuthenticationProcessingFilter(path);
        azureFilter.setRestTemplate(azureTemplate);
        azureFilter.setTokenServices(tokenServices);

        return azureFilter;
    }

    private Filter csrfHeaderFilter() {

        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                CsrfToken csrf = (CsrfToken) request
                        .getAttribute(CsrfToken.class.getName());
                if (csrf != null) {
                    Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
                    String token = csrf.getToken();
                    if (cookie == null
                            || token != null && !token.equals(cookie.getValue())) {
                        cookie = new Cookie("XSRF-TOKEN", token);
                        cookie.setPath("/");
                        response.addCookie(cookie);
                    }
                }
                filterChain.doFilter(request, response);
            }
        };
    }

    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }

}

class ClientResources {

    private OAuth2ProtectedResourceDetails client;
    private ResourceServerProperties resource;
    private AccessTokenProvider accessTokenProvider;

    public ClientResources() {

        client = new AuthorizationCodeResourceDetails();
        resource = new ResourceServerProperties();

        ClientCredentialsAccessTokenProvider clientCredentialsAccessTokenProvider = new ClientCredentialsAccessTokenProvider();
        ResourceOwnerPasswordAccessTokenProvider resourceOwnerPasswordAccessTokenProvider = new ResourceOwnerPasswordAccessTokenProvider();
        ImplicitAccessTokenProvider implicitAccessTokenProvider = new ImplicitAccessTokenProvider();
        AzureIdTokenProvider authorizationCodeAccessTokenProvider = new AzureIdTokenProvider();
        authorizationCodeAccessTokenProvider.setTokenRequestEnhancer(new AzureRequestEnhancer());

        accessTokenProvider = new AccessTokenProviderChain(Arrays.<AccessTokenProvider>asList(
                authorizationCodeAccessTokenProvider,
                implicitAccessTokenProvider,
                resourceOwnerPasswordAccessTokenProvider,
                clientCredentialsAccessTokenProvider));
    }

    public OAuth2ProtectedResourceDetails getClient() {
        return client;
    }

    public ResourceServerProperties getResource() {
        return resource;
    }

    public AccessTokenProvider getAccessTokenProvider() {
        return accessTokenProvider;
    }
}
