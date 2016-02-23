###General

This project is based of off the Spring Tutorial for using OAuth2.

    https://spring.io/guides/tutorials/spring-boot-oauth2/

- It has been modified to produce a war instead of a jar.
- The Java Version was changed to 7 instead of 8.
- You will need to modify the application.yml file to contain your customer name,
clientId, and clientSecret for AzureAD B2C.

###Notice
This currently is still a work in progress.
Although authentication has been performed successfully, the parsing of the
JWT token ("id_token") for use by Spring Security still needs to be done.

Any suggestions, help, and contributions will be appreciated.

### Azure Documentation and Resources

- **Main Documentation:** https://azure.microsoft.com/en-us/documentation/services/active-directory-b2c/
- **OpenId Connect:** https://azure.microsoft.com/en-us/documentation/articles/active-directory-b2c-reference-oidc/
- **OAuth2:** https://azure.microsoft.com/en-us/documentation/articles/active-directory-b2c-reference-oauth-code/
- **Policies:** https://github.com/Azure/azure-content/blob/master/articles/active-directory-b2c/active-directory-b2c-reference-policies.md

