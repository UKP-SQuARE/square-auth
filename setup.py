from setuptools import setup, find_packages

__version__ = "0.0.9"

setup(
    name="square_auth",
    version=__version__,
    license="MIT",
    description="",
    url="https://github.com/UKP-SQuARE/square-auth",
    download_url=f"https://github.com/UKP-SQuARE/square-auth/archive/refs/tags/v{__version__}.tar.gz",
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
