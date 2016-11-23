# Auth tokens for various providers, and how to get them

## Azure AD and windows live

https://azure.microsoft.com/en-us/documentation/articles/active-directory-v2-protocols-implicit/

```
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?scope=openid%20profile%20email%20Notes.ReadWrite&response_mode=fragment&nonce=12345&response_type=token+id_token&state=12345&client_id=client_id&redirect_url=redirect_url
```

```
email = token.preferred_username
```

```
IDS='q7z601 q7z602 q7z7m1 q86sm5 q86sm8 q86sp6 q86sq3 q86sq4 q86sq6';STAGE='test';TOKEN=$(curl --silent "https://$STAGE.glycocode.com/api/login" | tr -d '"'); for id in $IDS; do for i in `seq 1 10`; do curl --silent "https://$STAGE.glycocode.com/api/data/latest/combined/$id?" -o /dev/null -w %{time_connect}:%{time_starttransfer}:%{time_total} -H "authorization: Bearer $TOKEN" -H 'cache-control: no-cache' --compressed; echo " $STAGE $id $i"; sleep 0.5; done; done
```