# nodebb-plugin-sso-leapbase

NodeBB Plugin for SSO with leapbase

Forked from https://github.com/julianlam/nodebb-plugin-sso-oauth

# config.json

```
"oauth": {
  "name": "leapbase",
  "clientID": "<client id>",
  "clientSecret": "<client secret>",
  "authorizationURL": "<host>/oauth2orize_server/dialog/authorize",
  "tokenURL": "<host>/oauth2orize_server/token",
  "userRoute": "<host>/oauth2orize_server/userinfo", 
  "scope": "profile"
}
```
