package com.dogjaw.services.authentication;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * I'm actually not sure if I need this.
 *
 * I was getting some redirect errors for
 * /login/b2c, so I added this manual configuration.
 *
 * Some things have changed since then, so maybe
 * I'll try to take this out.
 */
@Configuration
public class MvcConfig extends WebMvcConfigurerAdapter {

//    @Value("${azure.open-id-connect.client.user-authorization-uri}")
//    private String signinUrl;
//
//    @Value("${azure.open-id-connect.client.client-id}")
//    private String clientId;
//
//    @Value("${azure.open-id-connect.client.scope}")
//    private String scope;
//
//    @Value("${azure.open-id-connect.client.redirect-url}")
//    private String redirectUrl;

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {


        registry.addViewController("/").setViewName("index");
        registry.addViewController("/login/azure").setViewName("index");
    }

//    @Override
//    public void addInterceptors(InterceptorRegistry registry) {
//
//        registry.addInterceptor(new UserInfoInterceptor());
//    }
//
//    private String azureLoginUrl(){
//
//        try {
//            return signinUrl+
//                    "&client_id="+URLEncoder.encode(clientId,"UTF-8")+
//                    "&scope="+URLEncoder.encode(scope,"UTF-8")+
//                    "&redirect_uri="+URLEncoder.encode(redirectUrl,"UTF-8");
//        }
//        catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//            throw new RuntimeException(e);
//        }
//    }
}
