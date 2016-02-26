package com.dogjaw.services.authentication.logging;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;

public class LoggingRequestInterceptor implements ClientHttpRequestInterceptor {

    private static final Log LOG = LogFactory.getLog(LoggingRequestInterceptor.class);

    @Override
    public ClientHttpResponse intercept(
            final HttpRequest request,
            final byte[] body,
            final ClientHttpRequestExecution execution) throws IOException {

        ClientHttpResponse response = execution.execute(request, body);
        log(request, body, response);
        return response;
    }

    @SuppressWarnings("UnusedParameters")
    private void log(
            final HttpRequest request,
            final byte[] body,
            final ClientHttpResponse response) throws IOException {

        LOG.debug("Taskman WS request issued: " + request.getMethod().toString() + " " + request.getURI().toString());
    }
}
