import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from pytest import fixture

def generate_private_public_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

@fixture
def token_pubkey_factory():
    def token_pubkey(**kwargs):
        private_key, public_key = generate_private_public_key()
        headers = kwargs.pop("headers", {})
        token = jwt.encode(headers=headers, payload=kwargs, key=private_key, algorithm="RS256")
        return token, public_key
    return token_pubkey
