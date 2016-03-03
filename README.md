###General

This project is based of off the Spring Tutorial for using OAuth2.

    https://spring.io/guides/tutorials/spring-boot-oauth2/

- It has been modified to produce a war instead of a jar.
- The Java Version was changed to 7 instead of 8.
- You will need to modify the application.yml file to contain your customer name,
clientId, and clientSecret for AzureAD B2C.

###Notice
The authentication and userdetails loading should now work.
HOWEVER, there are a few things I have not done/fixed yet. 
- RSA verification is not being done. Any help on this is appreciated.
- For some weird reason, after properly authenticating and loading the user, I am being redirected to the bootstrap.js file instead of back to the index. But if you see the javascript file, it means you are authenticated! If you manually navigate to the root path, you will see that you are logged in, and you should be able to log in and out at will (no more weird js files being loaded).


### Azure Documentation and Resources

- **Main Documentation:** https://azure.microsoft.com/en-us/documentation/services/active-directory-b2c/
- **OpenId Connect:** https://azure.microsoft.com/en-us/documentation/articles/active-directory-b2c-reference-oidc/
- **OAuth2:** https://azure.microsoft.com/en-us/documentation/articles/active-directory-b2c-reference-oauth-code/
- **Policies:** https://github.com/Azure/azure-content/blob/master/articles/active-directory-b2c/active-directory-b2c-reference-policies.md

