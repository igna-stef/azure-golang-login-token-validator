# azure-golang-login-token-validator

this is a simple backend developed in golang that serves to authenticate tokens generated by applications registered in azure active directory.

This api receives an http post with the id_token generated when you log into an azure application. 

The function of this api is to ensure the validity of that token, as well as if the token is expired, among other checks. 

If the token is valid, then it returns an http response saying "token valid", in case the token is not valid for some reason, it returns an http response with the reason why the token is not valid.

ATTENTION:
-all you have to do is to replace your client id, the tenant id, and the app secret value, generated in "App registrations" in azure AD.

![AZURE AD](https://github.com/igna-stef/azure-golang-login-token-validator/assets/127454179/1ffbb6d0-5710-4bf8-8ec8-f70f51e8bb8f)

IMPORTANT:
you should create a .env file in the same directory as the main.go file and it should look something like this:
![Captura de Pantalla 2023-07-05 a la(s) 12 58 35](https://github.com/igna-stef/azure-golang-login-token-validator/assets/127454179/36bf3a6a-a3f6-41ab-aeeb-f374ecf0d29b)
