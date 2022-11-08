install:
	pip install --upgrade pip
	pip install -r requirements.txt

install-dev:
	pip install --upgrade pip
	pip install -r requirements.dev.txt
	pre-commit install

format:
	black .
