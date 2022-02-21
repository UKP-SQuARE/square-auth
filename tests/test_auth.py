import datetime

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.datastructures import Headers

from square_auth.auth import Auth


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "auth_header", (True, False), ids=["with_auth_header", "no_auth_header"]
)
async def test_call(auth_header, mocker, token_pubkey_factory):
    mock_keycloak_api = mocker.patch("square_auth.auth.KeycloakAPI")
    keycloak_base_url = "keycloak_base_url"
    test_realm = "test-realm"
    test_issuer = f"{keycloak_base_url}/auth/realms/{test_realm}"
    test_kid = "test-kid"
    test_audience = "test-audience"
    test_jwks_uri = "test_jwks_uri"

    token, public_key = token_pubkey_factory(
        headers=dict(kid=test_kid),
        iss=test_issuer,
        aud=test_audience,
    )

    mock_keycloak_api().get_keycloak_jwks_uri.return_value = test_jwks_uri
    mock_keycloak_api().get_public_key.return_value = public_key

    auth = Auth(
        keycloak_base_url=keycloak_base_url,
        audience=test_audience,
    )
    if auth_header:
        request = Request(
            scope=dict(
                type="http", headers=Headers(dict(Authorization=f"Bearer {token}")).raw
            )
        )
        await auth(request)
        mock_keycloak_api().get_public_key.assert_called_with(
            kid=test_kid, jwks_uri=test_jwks_uri
        )
    else:
        request = Request(scope=dict(type="http", headers=Headers({})))
        with pytest.raises(HTTPException):
            await auth(request)


@pytest.mark.parametrize(
    "iss_valid,aud_valid",
    ((True, True), (True, False), (False, True)),
    ids=["all_valid", "audience_invalid", "issuer_invalid"],
)
def test_verify_token(iss_valid, aud_valid, mocker, token_pubkey_factory):
    mock_keycloak_api = mocker.patch("square_auth.auth.KeycloakAPI")
    keycloak_base_url = "keycloak_base_url"
    test_realm = "test-realm"
    test_issuer = f"{keycloak_base_url}/auth/realms/{test_realm}"
    test_audience = "test-audience"
    token, public_key = token_pubkey_factory(
        iss=test_issuer if iss_valid else test_issuer + "-invalid",
        aud=test_audience if aud_valid else "invalid-audience",
    )

    auth = Auth(
        keycloak_base_url=keycloak_base_url,
        audience=test_audience,
    )

    if iss_valid and aud_valid:
        auth.verify_token(token, public_key, expected_issuer=test_issuer)
    else:
        with pytest.raises(HTTPException):
            auth.verify_token(token, public_key, expected_issuer=test_issuer)


def test_verify_token_no_audience(mocker, token_pubkey_factory):
    mock_keycloak_api = mocker.patch("square_auth.auth.KeycloakAPI")
    keycloak_base_url = "keycloak_base_url"
    test_realm = "test-realm"
    test_issuer = f"{keycloak_base_url}/auth/realms/{test_realm}"
    test_audience = "test-audience"
    token, public_key = token_pubkey_factory(
        iss=test_issuer,
        aud=test_audience,
    )

    auth = Auth(
        keycloak_base_url=keycloak_base_url,
    )

    auth.verify_token(token, public_key, expected_issuer=test_issuer)


@pytest.mark.parametrize("roles", (None, "str", ["str1", "str2"], 123))
def test_roles_setter(roles, mocker):
    mock_keycloak_api = mocker.patch("square_auth.auth.KeycloakAPI")
    kwargs = dict(
        keycloak_base_url="keycloak_base_url",
        audience="",
        roles=roles,
    )
    if isinstance(roles, (type(None), str, list)):
        auth = Auth(**kwargs)
        assert isinstance(auth.roles, list)
    else:
        with pytest.raises(TypeError):
            auth = Auth(**kwargs)


@pytest.mark.parametrize(
    "authorized_roles,reqesting_roles,authorized",
    (
        (None, ["roleA"], True),
        ("roleA", ["roleA"], True),
        (["roleA", "roleB"], ["roleA"], True),
        (["roleA", "roleB"], ["roleC"], False),
    ),
)
def test_verify_roles(authorized_roles, reqesting_roles, authorized, mocker):
    mock_keycloak_api = mocker.patch("square_auth.auth.KeycloakAPI")
    payload = dict(realm_access=dict(roles=reqesting_roles))

    auth = Auth(
        keycloak_base_url="keycloak_base_url",
        audience="",
        roles=authorized_roles,
    )
    if authorized:
        auth.verify_roles(payload)
    else:
        with pytest.raises(HTTPException):
            auth.verify_roles(payload)


@pytest.mark.parametrize("expired", (True, False), ids=["expired", "not_expired"])
def test_expired_token(expired, token_pubkey_factory, mocker):
    mock_keycloak_api = mocker.patch("square_auth.auth.KeycloakAPI")
    keycloak_base_url = "keycloak_base_url"
    test_realm = "test-realm"
    test_issuer = f"{keycloak_base_url}/auth/realms/{test_realm}"
    test_audience = "test-audience"

    expires_at = datetime.datetime.now(tz=datetime.timezone.utc)
    if expired:
        expires_at -= datetime.timedelta(seconds=42)
    else:
        expires_at += datetime.timedelta(seconds=42)

    token, public_key = token_pubkey_factory(
        exp=expires_at, iss=test_issuer, aud=test_audience
    )
    mock_keycloak_api.get_public_key.return_value = public_key

    auth = Auth(
        keycloak_base_url=keycloak_base_url,
        audience=test_audience,
    )

    if expired:
        with pytest.raises(HTTPException):
            auth.verify_token(token, public_key, expected_issuer=test_issuer)
    else:
        auth.verify_token(token, public_key, expected_issuer=test_issuer)


def get_realm_from_token(token_pubkey_factory):
    expected_realm_name = "test-realm"
    token, _ = token_pubkey_factory(
        iss=f"http://host:port/path/to/the/{expected_realm_name}"
    )
    actual_realm_name = Auth.get_realm_from_token(token)
    assert expected_realm_name == actual_realm_name
