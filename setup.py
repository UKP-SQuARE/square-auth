from setuptools import setup, find_packages

setup(
    name="square_auth",
    version="0.0.2",
    description="",
    url="www.informatik.tu-darmstadt.de/ukp",
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
)
