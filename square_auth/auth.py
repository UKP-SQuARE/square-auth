import logging
import os
from typing import Dict, List, Union

import jwt
from fastapi import HTTPException
from fastapi.security.http import HTTPBearer, HTTPAuthorizationCredentials
from starlette.requests import Request

from square_auth.keycloak_api import KeycloakAPI

logger = logging.getLogger(__name__)


class Auth(HTTPBearer):
    def __init__(
        self,
        keycloak_base_url: str = None,
        audience: str = None,
        roles: Union[str, List[str]] = None,
    ) -> None:
        """Validates Access Tokens

        Args:
            keycloak_base_url (str): URL of the keycloak instance, if not set, will attempt to read from KEYCLOAK_BASE_URL environment variable.
            realm (str): Realm of the expected tokens.
            audience (str, optional): If provided, __call__ will check for correct audience in the token. Defaults to None.
            roles (Union[str, List[str]], optional): Checks whether any of the provided roles are in the token. Defaults to None.
        """
        super().__init__()
        self.keycloak_base_url = keycloak_base_url
        self.audience: str = audience
        self.roles: List[str] = roles

        self.keycloak_api = KeycloakAPI(keycloak_base_url)

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
    def roles(self):
        return self._roles

    @roles.setter
    def roles(self, value):
        if value is None:
            self._roles = []
        elif isinstance(value, str):
            self._roles = [value]
        elif isinstance(value, list):
            self._roles = value
        else:
            raise TypeError(
                f"Expected roles to be `str` or `list`, but got {type(value)}."
            )

    async def __call__(self, request: Request) -> Dict:
        """Check if the token in the request is valid and has the required roles."""
        # parse token
        authorization_credentials: HTTPAuthorizationCredentials = (
            await super().__call__(request)
        )
        encoded_token = authorization_credentials.credentials

        # get realm
        realm = self.get_realm_from_token(encoded_token)
        jwks_uri = self.keycloak_api.get_keycloak_jwks_uri(realm)

        # prepare validation
        unverified_token_header = jwt.get_unverified_header(encoded_token)
        public_key = self.keycloak_api.get_public_key(
            kid=unverified_token_header["kid"], jwks_uri=jwks_uri
        )
        expected_issuer = self.get_expected_issuer(realm)

        # validate
        payload: Dict = self.verify_token(encoded_token, public_key, expected_issuer)
        self.verify_roles(payload)

        return payload

    def verify_token(self, token: str, public_key, expected_issuer: str) -> Dict:
        """Verifies the tokens signature, expiration, issuer (and audience if set)"""

        decode_kwargs = dict(
            jwt=token,
            key=public_key,
            algorithms=["RS256"],
            issuer=expected_issuer,
        )
        if self.audience:
            decode_kwargs.update(audience=self.audience)
        else:
            decode_kwargs.update(options={"verify_aud": False})

        try:
            payload = jwt.decode(**decode_kwargs)
        except Exception as err:
            logger.exception(err)
            raise HTTPException(401)
        return payload

    def verify_roles(self, payload: Dict):
        """Verify if the token contains required roles"""

        if self.roles and not any(
            r in payload["realm_access"]["roles"] for r in self.roles
        ):
            # roles is not empty AND there has not been any overlap between roles in the
            # token and in the auth object
            raise HTTPException(401)

    @staticmethod
    def get_realm_from_token(token: str) -> str:
        payload = jwt.decode(token, options=dict(verify_signature=False))
        realm = payload["iss"][payload["iss"].rfind("/")+1:]

        return realm
    
    def get_expected_issuer(self, realm: str) -> str:
        return f"{self.keycloak_base_url}/auth/realms/{realm}"
