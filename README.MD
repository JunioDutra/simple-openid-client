# Simple openid Client

#### Client PUBLIC
when client public we gona use PKCE
```js
const OpenIdClient = new OpenIdClientClass();

await OpenIdClient.init({
  client_id: "ESPECIAL_CLIENT_ID",
  redirect_uris: ["http://localhost:3000/"],
  response_types: ["code"],
  grant_type: "authorization_code",
  authority: "https://openid.authserver.com/",
})

const url = await OpenIdClient.getRedirectUrl();
const token = await OpenIdClient.getTokens("lookMyCode")
```

#### Client CONFIDENTIAL
when client public we gona use secret
** only use CONFIDENTIAL, if can store secret in a safe way
```js
const OpenIdClient = new OpenIdClientClass();

await OpenIdClient.init({
  client_id: "ESPECIAL_CLIENT_ID",
  client_secret: "ESPECIAL_CLIENT_SECRET",
  redirect_uris: ["http://localhost:3000/"],
  response_types: ["code"],
  grant_type: "authorization_code",
  authority: "https://openid.authserver.com/",
})

const url = await OpenIdClient.getRedirectUrl();
const token = await OpenIdClient.getTokens("lookMyCode")
```