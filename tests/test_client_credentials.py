import datetime
from unittest.mock import patch

import pytest

from square_auth.client_credentials import ClientCredentials


@patch("square_auth.client_credentials.KeycloakAPI")
@pytest.mark.parametrize("expired", (True, False), ids=["expired", "not_expired"])
def test_client_credentails_call(mock_keycloak_api, expired, token_pubkey_factory):

    test_realm = "test-realm"
    test_client_id = "test-client-id"
    test_client_secret = "test-client-secret"

    expires_at = datetime.datetime.now(tz=datetime.timezone.utc)
    if expired:
        expires_at += datetime.timedelta(seconds=30)

    mock_keycloak_api().get_token_from_client_credentials.return_value = (
        token_pubkey_factory(exp=expires_at + datetime.timedelta(seconds=300))
    )

    token, _ = token_pubkey_factory(exp=expires_at)
    client_credentials = ClientCredentials(
        "keycloak_base_url",
        realm=test_realm,
        client_id=test_client_id,
        client_secret=test_client_secret,
        buffer=60,
    )
    client_credentials.token = token

    client_credentials()

    if expired:
        mock_keycloak_api().get_token_from_client_credentials(
            realm=test_realm, client_id=test_client_id, client_secret=test_client_secret
        )
