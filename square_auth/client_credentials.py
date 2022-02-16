import os
import requests
import jwt

from square_auth.keycloak_api import KeycloakAPI


class ClientCredentials:
    def __init__(
        self,
        keycloak_base_url: str,
        realm: str,
        client_id: str = None,
        client_secret: str = None,
        buffer: int = 60,
    ) -> None:
        self.keycloak_api = KeycloakAPI(keycloak_base_url)
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.buffer = buffer

        self.token = self.renew_token()

    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        if value is None:
            value = os.getenv("CLIENT_ID")
            if value is None:
                raise ValueError(
                    "Client ID not provided and not in environment variables."
                )
        self._client_id = value

    @property
    def client_secret(self):
        return self._client_secret

    @client_secret.setter
    def client_secret(self, value):
        if value is None:
            value = os.getenv("CLIENT_SECRET")
            if value is None:
                raise ValueError(
                    "Client Secret not provided and not in environment variables."
                )
        self._client_secret = value

    def __call__(self) -> str:
        """Return current token or obtain new one if current token is expired."""

        try:
            jwt.decode(
                self.token,
                options={"verify_signature": False, "verify_exp": True},
                leway=-self.buffer,
            )
        except jwt.exceptions.ExpiredSignatureError:
            self.renew_token()

        return self.token

    def renew_token(self):
        self.token = self.keycloak_api.get_token_from_client_credentials(
            realm=self.realm,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )
