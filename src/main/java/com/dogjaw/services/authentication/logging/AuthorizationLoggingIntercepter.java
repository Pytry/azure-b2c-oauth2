package com.dogjaw.services.authentication.logging;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;

/**
 * Created by Keith Hoopes on 2/3/2016.
 * Copyright Bear River Mutual 2016.
 */
public class AuthorizationLoggingIntercepter implements ClientHttpRequestInterceptor {

    private static final Log LOG = LogFactory.getLog(AuthorizationLoggingIntercepter.class);

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {

        ClientHttpResponse response = execution.execute(request, body);

        log(request,body,response);

        return response;
    }

    private void log(HttpRequest request, byte[] body, ClientHttpResponse response) throws IOException {

        String json = String.valueOf(body);
        LOG.info("Body:\n"+ json);
    }
}