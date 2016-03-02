package com.dogjaw.services.authentication;

import com.dogjaw.services.authentication.b2c.AzurePolicyConfiguration;
import com.dogjaw.services.authentication.b2c.AzurePolicyMetaData;
import com.dogjaw.services.authentication.b2c.MetaDataClient;
import com.dogjaw.services.authentication.b2c.RsaKeyClient;
import com.dogjaw.services.authentication.logging.LoggingRequestInterceptor;
import com.dogjaw.services.authentication.services.RsaKeyCachingService;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.NamedAdminAuthoritiesMapper;
import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.client.SubjectIssuerGrantedAuthority;
import org.mitre.openid.connect.client.service.impl.*;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.mitre.openid.connect.web.UserInfoInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.client.RestTemplate;
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
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;

/**
 * Created by Keith Hoopes on 2/1/2016.
 * Copyright Bear River Mutual 2016.
 */
//@RestController
@Configuration
@EnableWebSecurity
@Order(6)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

//    @SuppressWarnings("SpringJavaAutowiringInspection")
//    @Autowired
//    OAuth2ClientContext oauth2ClientContext;

    @Autowired
    RsaKeyCachingService rsaKeyCachingService;

    @Value("${azure.webfinger.force-https}")
    Boolean forceHttps;

//    @RequestMapping({"/user", "/me", "/users"})
//    public Map<String, String> user(Principal principal) {
//
//        Map<String, String> map = new LinkedHashMap<>();
//        map.put("name", principal.getName());
//        return map;
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authenticationProvider(openIdConnectAuthenticationProvider())
                .csrf().disable()
                .antMatcher("/**").authorizeRequests()
                .anyRequest().authenticated()
                .antMatchers("/webjars/**").permitAll().and()
                .exceptionHandling().authenticationEntryPoint(loginUrlAuthenticationEntryPoint()).and()
                .logout().logoutSuccessUrl("/loggedout").permitAll().and()
//                .csrf().csrfTokenRepository(csrfTokenRepository()).and()
//                .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
                .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//
//        auth
//
//    }

//    @Configuration
//    @EnableResourceServer
//    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
//
//        @Override
//        public void configure(HttpSecurity http) throws Exception {
//
//            http
//                    .antMatcher("/me")
//                    .authorizeRequests().anyRequest().authenticated();
//        }
//    }

    /**
     * AZURE BEANS
     */
    private static final int TIMEOUT = 30000;

    @Bean(name = "loginUrlAuthenticationEntryPoint")
    AuthenticationEntryPoint loginUrlAuthenticationEntryPoint() throws UnsupportedEncodingException {

        AuthorizationCodeResourceDetails details = oAuth2ProtectedResourceDetails();
        String userAuthorizationUri = details.getUserAuthorizationUri();
        String clientId = details.getClientId();
        String redirect = details.getPreEstablishedRedirectUri();
        String response_type = "code id_token";
        String response_mode = "form_post";
        String nonce = "dogjaw";
        List<String> scopeList = details.getScope();
        StringBuilder scope = new StringBuilder();
        for (int i = 0; i < scopeList.size(); i++) {
            String val = scopeList.get(i);
            if (i > 0) {
                scope.append(" ");
            }
            scope.append(val);
        }

        return new LoginUrlAuthenticationEntryPoint(
                userAuthorizationUri +
                        "&client_id=" + URLEncoder.encode(clientId, "UTF-8") +
                        "&scope=" + URLEncoder.encode(scope.toString(), "UTF-8") +
                        "&redirect_uri=" + URLEncoder.encode(redirect, "UTF-8") +
                        "&state=" + URLEncoder.encode("authenticating", "UTF-8") +
                        "&response_type=" + URLEncoder.encode(response_type, "UTF-8") +
                        "&response_mode=" + URLEncoder.encode(response_mode, "UTF-8") +
                        "&nonce=" + URLEncoder.encode(nonce, "UTF-8"));
    }

    @Bean(name = "jsonHttpHeaders")
    HttpHeaders jsonHttpHeaders() {

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/json");
        headers.add("Accept", "application/json");

        return headers;
    }

    @Bean(name = "commonRestTemplate")
    RestTemplate commonRestTemplate() {

        RestTemplate restTemplate = new RestTemplate(new SimpleClientHttpRequestFactory());
        restTemplate.getInterceptors().add(new LoggingRequestInterceptor());
//        restTemplate.setMessageConverters(Collections.<HttpMessageConverter<?>> singletonList(httpMessageConverter()));

        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setConnectTimeout(TIMEOUT);
        requestFactory.setReadTimeout(TIMEOUT);

        restTemplate.setRequestFactory(requestFactory);

        return restTemplate;
    }

    @Bean(name = "mappingJackson2HttpMessageConverter")
    MappingJackson2HttpMessageConverter httpMessageConverter() {

        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.registerModule(new Jackson2HalModule());

        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        converter.setSupportedMediaTypes(MediaType.parseMediaTypes("application/hal+json,application/json"));
        converter.setObjectMapper(mapper);

        return converter;
    }

    @Bean(name = "azurePolicyConfiguration")
    @ConfigurationProperties("azure.policy")
    AzurePolicyConfiguration azurePolicyConfiguration() {

        return new AzurePolicyConfiguration();
    }

    @Bean(name = "oAuth2ProtectedResourceDetails")
    @ConfigurationProperties("azure.open-id-connect.client")
    public AuthorizationCodeResourceDetails oAuth2ProtectedResourceDetails() {

        return new AuthorizationCodeResourceDetails();
    }

    @Bean(name = "metaDataClient")
    MetaDataClient metaDataClient() {

        MetaDataClient metaDataClient = new MetaDataClient();
        metaDataClient.setJsonHttpHeaders(jsonHttpHeaders());
        metaDataClient.setPolicy(azurePolicyConfiguration());
        metaDataClient.setRestTemplate(commonRestTemplate());

        return metaDataClient;
    }

    @Bean(name = "rsaKeyClient")
    RsaKeyClient rsaKeyClient() {

        RsaKeyClient rsaKeyClient = new RsaKeyClient();
        rsaKeyClient.setJsonHttpHeaders(jsonHttpHeaders());
        rsaKeyClient.setMetaDataClient(metaDataClient());
        rsaKeyClient.setRestTemplate(commonRestTemplate());
        rsaKeyClient.setPolicy(azurePolicyConfiguration());

        return rsaKeyClient;
    }

    //MITRE CONFIG

    @Bean(name = "userInfoInterceptor")
    public UserInfoInterceptor userInfoInterceptor() {
        return new UserInfoInterceptor();
    }

    @Bean
    public FilterRegistrationBean oidCAuthenticationFilter(OIDCAuthenticationFilter filter) {

        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);

        return registration;
    }

    @Bean(name = "openIdConnectAuthenticationProvider")
    OIDCAuthenticationProvider openIdConnectAuthenticationProvider() {

        OIDCAuthenticationProvider prov = new OIDCAuthenticationProvider();
        prov.setAuthoritiesMapper(namedAdminAuthoritiesMapper());

        return prov;
    }

    @Bean(name = "namedAdminAuthoritiesMapper")
    NamedAdminAuthoritiesMapper namedAdminAuthoritiesMapper() {

        NamedAdminAuthoritiesMapper mapper = new NamedAdminAuthoritiesMapper();
        mapper.setAdmins(namedAdmins());
        return mapper;
    }

    @Bean(name = "namedAdmins")
    Set<SubjectIssuerGrantedAuthority> namedAdmins() {

        Set<SubjectIssuerGrantedAuthority> set = new HashSet<>();
        AzurePolicyMetaData meta = metaDataClient().getSigninMetaData();
        List<String> subjects = meta.getSubjectTypesSupported();

        for (String subject : subjects) {

            SubjectIssuerGrantedAuthority auth = new SubjectIssuerGrantedAuthority(
                    subject,
                    meta.getIssuer());
            set.add(auth);
        }
        return set;
    }


    @Bean(name = "openIdConnectAuthenticationFilter")
    OIDCAuthenticationFilter openIdConnectAuthenticationFilter() throws Exception {

        OIDCAuthenticationFilter filter = new OIDCAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager());
        filter.setIssuerService(thirdPartyIssuerService());
        filter.setServerConfigurationService(dynamicServerConfigurationService());
        filter.setClientConfigurationService(dynamicClientConfigurationService());
        filter.setAuthRequestOptionsService(staticAuthRequestOptionsService());
        filter.setAuthRequestUrlBuilder(plainAuthRequestUrlBuilder());

        return filter;
    }

//    @Bean(name = "staticIssuerService")
//    StaticSingleIssuerService staticIssuerService() {
//
//        StaticSingleIssuerService issuerService = new StaticSingleIssuerService();
//        issuerService.setIssuer(metaDataClient().getSigninMetaData().getIssuer());
//
//        return issuerService;
//    }

//    @Bean(name = "webfingerIssuerService")
//    @ConfigurationProperties("azure.webfinger")
//    WebfingerIssuerService webfingerIssuerService() {
//
//        return new WebfingerIssuerService();
//    }

    @Bean(name = "thirdPartyIssuerService")
    @ConfigurationProperties("azure.webfinger")
    ThirdPartyIssuerService thirdPartyIssuerService() {

        ThirdPartyIssuerService thirdPartyIssuerService = new ThirdPartyIssuerService();
        AzurePolicyMetaData meta = metaDataClient().getSigninMetaData();
        thirdPartyIssuerService.setWhitelist(new HashSet<>(Collections.singletonList(meta.getIssuer())));
        thirdPartyIssuerService.setAccountChooserUrl(meta.getAuthorizationEndpoint());

        return thirdPartyIssuerService;
    }

//    @Bean(name = "hybridIssuerService")
//    HybridIssuerService hybridIssuerService() {
//
//        HybridIssuerService service = new HybridIssuerService();
//        /*
//        This default property forces the webfinger issuer URL to be HTTPS, turn off for development work
//         */
//        service.setForceHttps(forceHttps != null && forceHttps);
//        service.setLoginPageUrl("/");
//
//        return service;
//    }

    @Bean(name = "staticServerConfigurationService")
    StaticServerConfigurationService staticServerConfigurationService() {

        StaticServerConfigurationService configurationService = new StaticServerConfigurationService();
        configurationService.setServers(serverConfigurations());

        return configurationService;
    }

    @Bean(name = "staticServerConfiguration")
    @ConfigurationProperties("azure.open-id-connect.resource")
    ServerConfiguration staticServerConfiguration() {

        ServerConfiguration serverConfiguration = new ServerConfiguration();
        AzurePolicyMetaData metaData = metaDataClient().getSigninMetaData();
        serverConfiguration.setIssuer(metaData.getIssuer());
        serverConfiguration.setAuthorizationEndpointUri(metaData.getAuthorizationEndpoint());
        serverConfiguration.setTokenEndpointUri(metaData.getTokenEndpoint());
        serverConfiguration.setJwksUri(metaData.getJwksUri());
        serverConfiguration.setClaimsSupported(metaData.getClaimsSupported());
        serverConfiguration.setEndSessionEndpoint(metaData.getEndSessionEndpoint());
        serverConfiguration.setResponseTypesSupported(metaData.getResponseTypesSupported());
        serverConfiguration.setScopesSupported(metaData.getScopesSupported());

        return serverConfiguration;
    }

    private Map<String, ServerConfiguration> serverConfigurations() {

        Map<String, ServerConfiguration> configurationMap = new HashMap<>();
        configurationMap.put(
                oAuth2ProtectedResourceDetails().getAccessTokenUri(),
                staticServerConfiguration());

        return configurationMap;
    }

    @Bean(name = "dynamicServerConfigurationService")
    DynamicServerConfigurationService dynamicServerConfigurationService() {

        return new DynamicServerConfigurationService();
    }

    @Bean(name = "hybridServerConfigurationService")
    HybridServerConfigurationService hybridServerConfigurationService() {

        HybridServerConfigurationService hybridServerConfigurationService = new HybridServerConfigurationService();
        hybridServerConfigurationService.setServers(serverConfigurations());

        return hybridServerConfigurationService;
    }

    @Bean(name = "dynamicClientConfigurationService")
    DynamicRegistrationClientConfigurationService dynamicClientConfigurationService() {

        DynamicRegistrationClientConfigurationService service = new DynamicRegistrationClientConfigurationService();
        service.setTemplate(registeredClient());

//        service.setRegisteredClientService(registeredClientService());

        return service;
    }

//    @Bean(name = "registeredClientService")
//    JsonFileRegisteredClientService registeredClientService() {
//
//        JsonFileRegisteredClientService service = new JsonFileRegisteredClientService("/tmp/simple-web-app-clients.json");
//        return service;
//    }

    @Bean(name = "staticClientConfigurationService")
    StaticClientConfigurationService staticClientConfigurationService() {

        StaticClientConfigurationService service = new StaticClientConfigurationService();
        service.setClients(registeredClientMap());

        return service;
    }

    @Bean(name = "hybridClientConfigurationService")
    HybridClientConfigurationService hybridClientConfigurationService() {

        HybridClientConfigurationService service = new HybridClientConfigurationService();
        service.setClients(registeredClientMap());
        service.setTemplate(registeredClient());
//        service.setRegisteredClientService(registeredClientService());

        return service;
    }

    @Bean(name = "staticAuthRequestOptionsService")
    StaticAuthRequestOptionsService staticAuthRequestOptionsService() {

        StaticAuthRequestOptionsService service = new StaticAuthRequestOptionsService();
        HashMap<String, String> options = new HashMap<>(2);
        AuthorizationCodeResourceDetails resource = oAuth2ProtectedResourceDetails();
        List<String> scopeList = resource.getScope();
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < scopeList.size(); i++) {

            if (i > 0) {
                builder.append(" ");
            }
            builder.append(scopeList.get(i));
        }
        options.put("scope", builder.toString());
        options.put("client_id", resource.getClientId());

        service.setOptions(options);

        return service;
    }

    @Bean(name = "plainAuthRequestUrlBuilder")
    PlainAuthRequestUrlBuilder plainAuthRequestUrlBuilder() {

        return new PlainAuthRequestUrlBuilder();
    }

//    @Bean(name = "signedAuthRequestUrlBuilder")
//    SignedAuthRequestUrlBuilder signedAuthRequestUrlBuilder() throws InvalidKeySpecException, NoSuchAlgorithmException {
//
////        AzurePolicyMetaData metaData = metaDataClient().getSigninMetaData();
//        SignedAuthRequestUrlBuilder builder = new SignedAuthRequestUrlBuilder();
//        builder.setSigningAndValidationService(defaultSignerService());
//
//        return builder;
//    }

    @Bean(name = "encryptedAuthRequestUrlBuilder")
    EncryptedAuthRequestUrlBuilder encryptedAuthRequestUrlBuilder() {

        EncryptedAuthRequestUrlBuilder builder = new EncryptedAuthRequestUrlBuilder();
        builder.setEncrypterService(clientKeyCacheService());
        builder.setAlg(JWEAlgorithm.RSA1_5);
        builder.setEnc(EncryptionMethod.A128GCM);

        return builder;
    }

    @Bean(name = "clientKeyCacheService")
    JWKSetCacheService clientKeyCacheService() {

        return new JWKSetCacheService();
    }

//    @Bean(name = "defaultSignerService")
//    DefaultJWTSigningAndValidationService defaultSignerService() throws InvalidKeySpecException, NoSuchAlgorithmException {
//
//        DefaultJWTSigningAndValidationService service = new DefaultJWTSigningAndValidationService(defaultKeyStore());
//        service.setDefaultSignerKeyId("rsa1");
//        service.setDefaultSigningAlgorithmName("RS256");
//
//        return service;
//    }

//    @Bean(name="clientKeyPublisher")
//    ClientKeyPublisher clientKeyPublisher() throws InvalidKeySpecException, NoSuchAlgorithmException {
//
//        ClientKeyPublisher clientKeyPublisher = new ClientKeyPublisher();
//        clientKeyPublisher.setJwkPublishUrl("jwk");
//        clientKeyPublisher.setSigningAndValidationService(defaultSignerService());
//
//        return clientKeyPublisher;
//    }

    @Bean(name = "registeredClient")
    @ConfigurationProperties("azure.open-id-connect")
    RegisteredClient registeredClient() {

        RegisteredClient registeredClient = new RegisteredClient();
        registeredClient.setTokenEndpointAuthMethod(ClientDetailsEntity.AuthMethod.SECRET_JWT);
        return registeredClient;
    }

    @Bean(name = "registeredClientMap")
    Map<String, RegisteredClient> registeredClientMap() {

        RegisteredClient registeredClient = registeredClient();

        Map<String, RegisteredClient> clientMap = new HashMap<>(1);
        clientMap.put(registeredClient().getRegistrationClientUri(), registeredClient);

        return clientMap;
    }


    @Bean(name = "defaultKeyStore")
    @ConfigurationProperties("azure.keystore")
    JWKSetKeyStore defaultKeyStore() {

        return new JWKSetKeyStore();
    }

    private Filter ssoFilter() throws Exception {

        CompositeFilter filter = new CompositeFilter();

        List<Filter> filters = new ArrayList<>();
        filters.add(openIdConnectAuthenticationFilter());
        filter.setFilters(filters);

        return filter;
    }

    @Bean(name = "csrfHeaderFilter")
    Filter csrfHeaderFilter() {

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

    /**
     * This is used for Angularjs.
     *
     * @return CsrfTokenRepository
     */
    @Bean(name = "csrfTokenRepository")
    CsrfTokenRepository csrfTokenRepository() {

        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");

        return repository;
    }
}