import os
import requests
import jwt

from square_auth.keycloak_api import KeycloakAPI


class ClientCredentials:
    def __init__(
        self,
        keycloak_base_url: str = None,
        realm: str = None,
        client_id: str = None,
        client_secret: str = None,
        buffer: int = 30,
    ) -> None:
        """Obtains Access Tokens via Client Credentials flow.

        Args:
            realm (str, optional): Realm of the expected tokens. If not set, will attempt to read from `REALM` environment variable. Defaults to None.
            keycloak_base_url (str, optional): URL of the keycloak instance, if not set, will attempt to read from `KEYCLOAK_BASE_URL` environment variable. Defaults to None.
            client_id (str, optional): The Client ID used for requesting access tokens. If not set, will attempt to read from `CLIENT_ID` environment variable. Defaults to None.
            client_secret (str, optional): The Client Secret used for requesting access tokens. If not set, will attempt to read from `CLIENT_SECERT` environment variable. Defaults to None.
            buffer (int, optional): Returned tokens are at least `buffer` seconds valid. Defaults to 30.
        """
        self.keycloak_base_url = keycloak_base_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.buffer = buffer

        self.keycloak_api = KeycloakAPI(self.keycloak_base_url)
        self.token = None

    @property
    def keycloak_base_url(self):
        return self._keycloak_base_url

    @keycloak_base_url.setter
    def keycloak_base_url(self, value):

        if value is None:
            value = os.getenv("KEYCLOAK_BASE_URL", None)
            if value is None:
                raise ValueError(
                    "Either provide keycloak_base_url as parameter or set "
                    "KEYCLOAK_BASE_URL environment variable."
                )
        self._keycloak_base_url = value

    @property
    def realm(self):
        return self._realm

    @realm.setter
    def realm(self, value):

        if value is None:
            value = os.getenv("REALM", None)
            if value is None:
                raise ValueError(
                    "Either provide realm as parameter or set REALM environment "
                    "variable."
                )
        self._realm = value

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
        """Returns access token that is at least `self.buffer` seconds valid."""

        if self.token is None:
            self.renew_token()

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
        """Obtinas a new token from keycloak using client credentials flow"""
        self.token = self.keycloak_api.get_token_from_client_credentials(
            realm=self.realm,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )
