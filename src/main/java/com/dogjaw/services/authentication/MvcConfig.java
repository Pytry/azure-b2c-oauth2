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

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {

        registry.addViewController("/home").setViewName("index");
        registry.addViewController("/").setViewName("index");
        registry.addViewController("/login").setViewName("index");
        registry.addViewController("/login/azure").setViewName("index");
        registry.addViewController("/login/github").setViewName("index");
    }
}
