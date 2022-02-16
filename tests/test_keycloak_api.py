import uuid

import jwt
import pytest
from keycloak import KeycloakAdmin, KeycloakOpenID

from square_auth.keycloak_api import KeycloakAPI
from tests.testcontainer_keycloak import TestcontainerKeycloak

@pytest.fixture(scope="session")
def keycloak():
    with TestcontainerKeycloak("jboss/keycloak:16.1.1") as kc:
        yield kc


@pytest.fixture(scope="session")
def kc_master(keycloak):
    return KeycloakAdmin(
        server_url=f"{keycloak.get_connection_url()}/auth/",
        username="admin",
        password="admin",
        realm_name="master",
        verify=True,
    )


@pytest.fixture(scope="session")
def kc_realm_factory(keycloak):
    def kc_realm(realm: str):
        return KeycloakAdmin(
            server_url=f"{keycloak.get_connection_url()}/auth/",
            username="admin",
            password="admin",
            realm_name=realm,
            user_realm_name="master",
            verify=True,
        )

    return kc_realm


@pytest.fixture
def create_realm_factory(kc_master):
    def create_realm(**kwargs):
        return kc_master.create_realm(
            payload={
                "id": "newrealm",
                "realm": "newrealm",
                "displayName": "New Realm",
                "enabled": True,
                "sslRequired": "external",
                "registrationAllowed": False,
                "loginWithEmailAllowed": True,
                "duplicateEmailsAllowed": False,
                "resetPasswordAllowed": False,
                "editUsernameAllowed": False,
                "bruteForceProtected": True,
                **kwargs,
            },
            skip_exists=True,
        )

    return create_realm


@pytest.fixture
def create_user_factory():
    def create_user(kc, **kwargs):
        return kc.create_user(
            {
                # "email": "example@example.com",
                "username": "example@example.com",
                "enabled": True,
                "firstName": "Example",
                "lastName": "Example",
                "credentials": [
                    {
                        "value": "password",
                        "type": "password",
                    }
                ],
                **kwargs,
            },
            exist_ok=True,
        )

    return create_user


@pytest.fixture
def token_factory():
    def token(server_url, username, password, realm, client_id="admin-cli"):
        keycloak_openid = KeycloakOpenID(
            server_url=server_url, realm_name=realm, client_id=client_id
        )
        return keycloak_openid.token(username, password)

    return token


@pytest.fixture
def create_client_credentials_factory():
    def create_client(kc, **kwargs):
        return kc.create_client(
            {
                "id": str(uuid.uuid1()),
                "clientId": "client",
                "enabled": True,
                "clientAuthenticatorType": "client-secret",
                "secret": "secret",
                "consentRequired": False,
                "standardFlowEnabled": False,
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": True,
                "publicClient": False,
                "frontchannelLogout": False,
                "protocol": "openid-connect",
                **kwargs,
            },
            skip_exists=True
        )

    return create_client


def test_auth_jwks_uri(keycloak, create_realm_factory):

    keycloak_base_url = keycloak.get_connection_url()
    test_realm = "test-realm-jwks-uri"

    _ = create_realm_factory(id=test_realm, realm=test_realm)

    keycloak_api = KeycloakAPI(keycloak_base_url)
    actual_jwks_uri = keycloak_api.get_keycloak_jwks_uri(test_realm)
    expected_jwks_uri = (
        f"{keycloak_base_url}/auth/realms/{test_realm}/protocol/openid-connect/certs"
    )
    assert actual_jwks_uri == expected_jwks_uri


def test_get_public_key(
    keycloak, create_realm_factory, kc_realm_factory, create_user_factory, token_factory
):

    keycloak_base_url = keycloak.get_connection_url()
    test_realm = "test-realm-public-key"
    test_username = "test-username"

    _ = create_realm_factory(id=test_realm, realm=test_realm)
    kc = kc_realm_factory(realm=test_realm)
    _ = create_user_factory(kc=kc, username=test_username)
    token = token_factory(
        server_url=keycloak_base_url + "/auth/",
        realm=test_realm,
        username=test_username,
        password="password",
    )
    header = jwt.get_unverified_header(token["access_token"])

    keycloak_api = KeycloakAPI(keycloak_base_url)
    jwks_uri = keycloak_api.get_keycloak_jwks_uri(realm=test_realm)

    public_key = keycloak_api.get_public_key(kid=header["kid"], jwks_uri=jwks_uri)


def test_get_token_from_client_credentials(
    keycloak, create_realm_factory, kc_realm_factory, create_client_credentials_factory
):
    keycloak_base_url = keycloak.get_connection_url()
    test_realm = "test-realm-client-credentials"
    test_client_id = "test-client"
    test_client_secret = "secret"
    _ = create_realm_factory(id=test_realm, realm=test_realm)
    kc = kc_realm_factory(test_realm)
    create_client_credentials_factory(
        kc, clientId=test_client_id, secret=test_client_secret
    )

    keycloak_api = KeycloakAPI(keycloak_base_url)
    token = keycloak_api.get_token_from_client_credentials(
        realm=test_realm, client_id=test_client_id, client_secret=test_client_secret
    )

    header = jwt.get_unverified_header(token)
    jwks_uri = keycloak_api.get_keycloak_jwks_uri(realm=test_realm)
    public_key = keycloak_api.get_public_key(kid=header["kid"], jwks_uri=jwks_uri)

    payload = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_aud": False})
    assert payload["clientId"] == test_client_id
