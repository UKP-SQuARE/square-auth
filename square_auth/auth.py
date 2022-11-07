import logging
import os
from typing import Dict, List, Union

import jwt
from fastapi import HTTPException
from fastapi.security.http import HTTPBearer, HTTPAuthorizationCredentials
from starlette.requests import Request

from square_auth.keycloak_client import KeycloakClient
from square_auth import utils

logger = logging.getLogger(__name__)


class Auth(HTTPBearer):
    def __init__(
        self,
        keycloak_base_url: str = None,
        audience: str = None,
        roles: Union[str, List[str]] = None,
        return_token_values: List[str] = None,
    ) -> None:
        """Validates Access Tokens

        Args:
            keycloak_base_url (str): URL of the keycloak instance, if not set, will attempt to read from KEYCLOAK_BASE_URL environment variable.
            audience (str, optional): If provided, __call__ will check for correct audience in the token. Defaults to None.
            roles (Union[str, List[str]], optional): Checks whether any of the provided roles are in the token. Defaults to None.
            return_token_values (List[str]], optional): List of keys that should be added from the token payload to the return value of __call__.

        """
        super().__init__()
        self.audience: str = audience
        self.roles: List[str] = roles
        self.return_token_values: List[str] = return_token_values
        self._is_local_deployment = utils.is_local_deployment()
        if self._is_local_deployment:
            _, self._public_key = utils.generate_token_pubkey()

        if not self._is_local_deployment:
            self.keycloak_base_url = keycloak_base_url
            self.keycloak_client = KeycloakClient(self.keycloak_base_url)

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
        if self._is_local_deployment:
            # local deployment, skip keycloak
            public_key = self._public_key
        else:
            jwks_uri = self.keycloak_client.get_keycloak_jwks_uri(realm)

            # prepare validation
            unverified_token_header = jwt.get_unverified_header(encoded_token)
            public_key = self.keycloak_client.get_public_key(
                kid=unverified_token_header["kid"], jwks_uri=jwks_uri
            )

        expected_issuer = self.get_expected_issuer(realm)

        # validate
        payload: Dict = self.verify_token(encoded_token, public_key, expected_issuer)
        self.verify_roles(payload)

        return self.prepare_return_from_payload(
            payload=payload, realm=realm, keys=self.return_token_values
        )

    def verify_token(self, token: str, public_key, expected_issuer: str) -> Dict:
        """Verifies the tokens signature, expiration, issuer (and audience if set)"""

        decode_kwargs = dict(
            jwt=token,
            key=public_key,
            algorithms=["RS256"],
            issuer=expected_issuer,
        )
        decode_kwargs_options = {}

        if self.audience:
            decode_kwargs.update(audience=self.audience)
        else:
            decode_kwargs_options.update({"verify_aud": False})

        if os.getenv("VERIFY_ISSUER", "1") != "1" or self._is_local_deployment:
            decode_kwargs_options.update({"verify_iss": False})

        decode_kwargs["options"] = decode_kwargs_options

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
        realm = payload["iss"][payload["iss"].rfind("/") + 1 :]

        return realm

    def get_expected_issuer(self, realm: str) -> str:
        if self._is_local_deployment:
            expected_issuer = "/LOCAL_SQUARE_REALM"
        else:
            expected_issuer = f"{self.keycloak_base_url}/auth/realms/{realm}"
        return expected_issuer

    @staticmethod
    def prepare_return_from_payload(
        payload: Dict, realm: str, keys: List[str] = None
    ) -> Dict:
        return_dict: Dict = dict(realm=realm, username=payload["preferred_username"])
        if keys is None:
            keys = []
        for k in keys:
            return_dict.update({k: payload[k]})

        return return_dict
