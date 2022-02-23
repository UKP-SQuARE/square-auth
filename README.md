# SQuARE-Auth

This package is part of [UKP-SQuARE](https://square.ukp-lab.de/).

This package provides utilities for securting APIs and for requesting access tokens via the client credentials flow.

## API Securing
In order to make an endpoint secure, i.e. to only permit authenticated and authorzied requests, an access token has to be sent with the request in the header. The `Auth` class can then check if this token is valid. It does so by checking whether  
(1) its contents are untampered with (signature check with public key),  
(2) the issuer and the audience are as specified and  
(3) the token has the required roles to access the resource.  
If any of these checks fail, the endpoint will return an Unauthorized/Unauthenticated error.

```python3
from fastapi import Depends, FastAPI
from square_auth.auth import Auth

app = FastAPI()

auth = Auth(
    keycloak_base_url="http://localhost:8080",
    audience="audience",
    roles="user",
)

@app.get("/items")
def get_items(token = Depends(auth)):
    return ["apple", "orange"]
```

The arguments to `Auth` are optional. The keycloak_base_url can be set via the environment variable `KEYCLOAK_BASE_URL`. If audience is not set, the `aud` field in the token will not be checked. If roles is not set, no check on the roles will be performed.

## Client Tokens
In order for services to access protected resources they also require an access token. A service can obtain a token from the identity provider by using the Client Credentials flow. For this the client first needs to be registered at the identity provider, where also the `client_id` and the `client_secret` will be issued. Given these credentials, tokens can be requested and used to ccess protected resources.

```python3
import requests
from square_auth.client_credentials import ClientCredentials

client_credentials = ClientCredentials(
    keycloak_base_url="http://localhost:8080",
    realm="test-realm",
    client_id="test-client",
    client_secret"d2031fb2-8fcb-11ec-8550-acbc3285a11b",
    buffer=60,
)

response = requests.get(
    "http://localhost/api/protcted-resource", 
    headers={"Authorization": f"Bearer {client_credentials()}"}
)
```
### Register a Client in Keycloak
1. Login to the admin console of Keycloak.
2. Select the realm where you want the Client to be created.
3. Go to Clients, and click create.
4. Enter a Client ID, ideally this should be similar to the service/application using the client.
5. In the client settings:
    - Set the Access Type to confidential
    - Disable Standard Flow and Direct Access Grant
    - Enable Service Accounts
    - Save
6. In the credentials tab you will find the current Client Secret. Regenerate the secret if it has been leaked accidentally. 
