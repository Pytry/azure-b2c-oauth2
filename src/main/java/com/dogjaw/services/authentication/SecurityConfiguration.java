package com.dogjaw.services.authentication;

import com.dogjaw.services.authentication.b2c.*;
import com.dogjaw.services.authentication.logging.AuthorizationLoggingIntercepter;
import com.dogjaw.services.authentication.logging.LoggingRequestInterceptor;
import com.dogjaw.services.authentication.services.RsaKeyCachingService;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.hateoas.hal.Jackson2HalModule;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
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
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.CompositeFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;
import sun.security.rsa.RSAPublicKeyImpl;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Principal;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * Created by Keith Hoopes on 2/1/2016.
 * Copyright Bear River Mutual 2016.
 */
@RestController
@Configuration
@EnableOAuth2Client
@EnableWebSecurity
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

        http
                .antMatcher("/**").authorizeRequests()
                .anyRequest().authenticated()
                .antMatchers("/", "/login**", "/webjars/**").permitAll().and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and()
                .logout().logoutSuccessUrl("/").permitAll().and()
                .csrf().csrfTokenRepository(csrfTokenRepository()).and()
                .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
                .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
    }

    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        @Override
        public void configure(HttpSecurity http) throws Exception {

            http
                    .antMatcher("/me")
                    .authorizeRequests().anyRequest().authenticated();
        }
    }

    private static final int TIMEOUT = 30000;

    @Bean(name = "jsonHttpHeaders")
    HttpHeaders jsonHttpHeaders(){

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/json");
        headers.add("Accept", "application/json");

        return headers;
    }

    @Bean(name="commonRestTemplate")
    RestTemplate commonRestTemplate(){

        RestTemplate restTemplate = new RestTemplate(new SimpleClientHttpRequestFactory());
        restTemplate.getInterceptors().add(new LoggingRequestInterceptor());
//        restTemplate.setMessageConverters(Collections.<HttpMessageConverter<?>> singletonList(httpMessageConverter()));

        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setConnectTimeout(TIMEOUT);
        requestFactory.setReadTimeout(TIMEOUT);

        restTemplate.setRequestFactory(requestFactory);

        return restTemplate;
    }

    @Bean(name="mappingJackson2HttpMessageConverter")
    MappingJackson2HttpMessageConverter httpMessageConverter(){

        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.registerModule(new Jackson2HalModule());

        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        converter.setSupportedMediaTypes(MediaType.parseMediaTypes("application/hal+json,application/json"));
        converter.setObjectMapper(mapper);

        return converter;
    }
    @Bean(name="oauth2ClientFilterRegistration")
    @Autowired
    public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {

        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);

        return registration;
    }

    @Bean(name="azurePolicyConfiguration")
    @ConfigurationProperties("azure.policy")
    AzurePolicyConfiguration azurePolicyConfiguration() {

        return new AzurePolicyConfiguration();
    }

    @Bean(name="clientDetails")
    @ConfigurationProperties("azure.client")
    ClientDetails clientDetails(){

        return new BaseClientDetails();
    }

    @Bean(name="oAuth2ProtectedResourceDetails")
    @ConfigurationProperties("azure.client")
    public OAuth2ProtectedResourceDetails oAuth2ProtectedResourceDetails(){

        return new ClientCredentialsResourceDetails();
    }

    @Bean(name="accessTokenProvider")
    public AccessTokenProvider accessTokenProvider() {


        ClientCredentialsAccessTokenProvider clientCredentialsAccessTokenProvider = new ClientCredentialsAccessTokenProvider();
        AzureIdTokenProvider authorizationCodeAccessTokenProvider = new AzureIdTokenProvider();
        authorizationCodeAccessTokenProvider.setTokenRequestEnhancer(new AzureRequestEnhancer());

        return new AccessTokenProviderChain(Collections.<AccessTokenProvider>singletonList(
                clientCredentialsAccessTokenProvider));
    }

    @Bean(name="metaDataClient")
    MetaDataClient metaDataClient(){

        MetaDataClient metaDataClient = new MetaDataClient();
        metaDataClient.setJsonHttpHeaders(jsonHttpHeaders());
        metaDataClient.setPolicy(azurePolicyConfiguration());
        metaDataClient.setRestTemplate(commonRestTemplate());

        return metaDataClient;
    }

    @Bean(name="rsaKeyClient")
    RsaKeyClient rsaKeyClient(){

        RsaKeyClient rsaKeyClient = new RsaKeyClient();
        rsaKeyClient.setJsonHttpHeaders(jsonHttpHeaders());
        rsaKeyClient.setMetaDataClient(metaDataClient());
        rsaKeyClient.setRestTemplate(commonRestTemplate());
        rsaKeyClient.setPolicy(azurePolicyConfiguration());

        return rsaKeyClient;
    }

    @Bean(name="clientDetailsService")
    ClientDetailsService clientDetailsService(){

        ClientDetails details = clientDetails();
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        Map<String, ClientDetails> detailsMap = new HashMap<>(1);
        detailsMap.put(details.getClientId(),details);
        clientDetailsService.setClientDetailsStore(detailsMap);

        return clientDetailsService;
    }
    private Filter ssoFilter() throws Exception {

        CompositeFilter filter = new CompositeFilter();

        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilter("/login/azure"));
        filter.setFilters(filters);

        return filter;
    }

    @Bean(name="jwtAccessTokenConverter")
    JwtAccessTokenConverter jwtAccessTokenConverter() throws InvalidKeyException, IOException {

        AzureRsaKeys rsaKey = rsaKeyCachingService.getSigninRsaKey();
        RsaKeyB2C rsaKeyB2C = rsaKey.getKeys().get(0);
//        AzurePolicyMetaData metaData = metaDataClient().getSigninMetaData();
//
//        BigInteger modulus = new BigInteger(rsaKeyB2C.getN());
//        BigInteger privateExponent = new BigInteger(rsaKeyB2C.getE());
//        RSAPrivateKeySpec rsaPrivateCrtKeySpec = new RSAPrivateKeySpec(
//                modulus, privateExponent
//        );
//        String clientSecret = oAuth2ProtectedResourceDetails().getClientSecret();
//        jwtTokenEnhancer.setVerifierKey(clientSecret);
//        jwtTokenEnhancer.setSigningKey(clientSecret);
        AzureJwtAccessTokenConverter azureJwtAccessTokenConverter = new AzureJwtAccessTokenConverter();

        RSAPublicKey rsaPublicKey = new RSAPublicKeyImpl(rsaKeyB2C.getE().getBytes());
        azureJwtAccessTokenConverter.setVerifierKey(new String(rsaPublicKey.getEncoded()));
        return azureJwtAccessTokenConverter;
    }

    @Autowired
    private RsaKeyCachingService rsaKeyCachingService;

    private Filter ssoFilter(String path) throws Exception {


        JwtAccessTokenConverter jwtTokenEnhancer = jwtAccessTokenConverter();
        JwtTokenStore jwtTokenStore = new JwtTokenStore(jwtTokenEnhancer);
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(jwtTokenStore);
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.afterPropertiesSet();

        OAuth2RestTemplate azureTemplate = new OAuth2RestTemplate(
                oAuth2ProtectedResourceDetails(),
                oauth2ClientContext
        );
        azureTemplate.setAccessTokenProvider(accessTokenProvider());
        azureTemplate.getInterceptors().add(new AuthorizationLoggingIntercepter());

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