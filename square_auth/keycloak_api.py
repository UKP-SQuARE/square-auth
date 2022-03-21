from functools import lru_cache
from typing import Dict, List
from urllib.parse import urlparse
import logging

import requests
from cryptography.x509 import load_pem_x509_certificate
from fastapi import HTTPException

logger = logging.getLogger(__name__)


class KeycloakAPI:
    def __init__(self, keycloak_base_url: str) -> None:
        """Utiliy class for interacting with Keycloak

        Args:
            keycloak_base_url (str): URL of the keycloak instance.
        """
        self.keycloak_base_url = keycloak_base_url

    @lru_cache(maxsize=1024)
    def get_keycloak_jwks_uri(self, realm: str) -> str:
        """Returns the endpoint for obtaining key certificates (public/private keys)"""
        response = requests.get(
            f"{self.keycloak_base_url}/auth/realms/{realm}/.well-known/openid-configuration"
        )
        jwks_uri = response.json()["jwks_uri"]

        # check if keycloak base url is differnt from return jwks uri
        # if true replace host
        jwks_parsed_uri = urlparse(jwks_uri)
        keycloak_parsed_url = urlparse(self.keycloak_base_url)
        if  jwks_parsed_uri.netloc != keycloak_parsed_url.netloc:
            jwks_uri = jwks_parsed_uri._replace(
                scheme=keycloak_parsed_url.scheme, netloc=keycloak_parsed_url.netloc
            ).geturl()


        return jwks_uri

    @staticmethod
    @lru_cache(maxsize=1024)
    def get_public_key(kid: str, jwks_uri: str):
        """Requests public key from the Identity Provider if not cached"""
        response = requests.get(jwks_uri)
        keys: List[Dict] = response.json()["keys"]
        key = list(filter(lambda k: k["kid"] == kid, keys))[0]
        if not key:
            logger.info(
                "Access Token received with kid not matching any keys on Auth server."
            )
            raise HTTPException(401)

        certificate_content = key["x5c"][0]
        certificate = (
            b"-----BEGIN CERTIFICATE-----\n"
            + str.encode(certificate_content)
            + b"\n-----END CERTIFICATE-----"
        )
        public_key = load_pem_x509_certificate(certificate).public_key()

        return public_key

    def get_token_from_client_credentials(
        self, realm: str, client_id: str, client_secret: str
    ):
        """Requests and returns new access token via client credentials flow."""
        response = requests.post(
            f"{self.keycloak_base_url}/auth/realms/{realm}/protocol/openid-connect/token",
            data=dict(
                grant_type="client_credentials",
                client_id=client_id,
                client_secret=client_secret,
            ),
        )
        response.raise_for_status()

        token = response.json()["access_token"]

        return token
