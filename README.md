# Auth tokens for various providers, and how to get them

## Azure AD and windows live

https://azure.microsoft.com/en-us/documentation/articles/active-directory-v2-protocols-implicit/

```
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?scope=openid%20profile%20email%20Notes.ReadWrite&response_mode=fragment&nonce=12345&response_type=token+id_token&state=12345&client_id=client_id&redirect_url=redirect_url
```

```
email = token.preferred_username
```