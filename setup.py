from setuptools import setup, find_packages

setup(
    name="square_auth",
    version="0.0.7",
    license="MIT",
    description="",
    url="https://github.com/UKP-SQuARE/square-auth",
    download_url="https://github.com/UKP-SQuARE/square-auth/archive/refs/tags/v0.0.7.tar.gz",
    author="UKP",
    author_email="baumgaertner@ukp.informatik.tu-darmstadt.de",
    packages=find_packages(
        exclude=("tests", ".gitignore", "requirements.dev.txt", "pytest.ini")
    ),
    install_requires=[
        "pyjwt[crypto]>=2.3.0",
        "requests>=2.26.0",
        "fastapi>=0.73.0",
    ],
    entry_points={
        "console_scripts": [
            "square_pk=square_auth.utils:generate_and_dump_private_key"
        ],
    },
)
