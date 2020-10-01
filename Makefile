APP_NAME=github.com/goolanger/swaggerize-auth

CERTS_FOLDER=data/certs
LOGS_FOLDER=data/logs
BIN_FOLDER=data/bin
CERTS_FOLDER=data/certs

CMD_EXEC=./cmd

# Generates the swagger definitions given the specs
swagger:
	go run $(CMD_EXEC)/swagger

# Generates the api specs for golang app
api_server:
	swagger generate server \
	--name $(APP_NAME) \
	--main-package main \
	--server-package server \
	--principal models.Claims \
	--quiet \
	--log-output=$(LOGS_FOLDER)/swagger-generator.logs

api_client:
	swagger generate client \
	--name $(APP_NAME)/test \
	--target test \
	--log-output=$(LOGS_FOLDER)/swagger-generator-tests.logs

api: api_server api_client

# Creates swagger specs, generates the api and runs the server
swaggerize: swagger api

# Makes all external files to go binaries
bindata-views:
	go-bindata -pkg auth -o pkg/auth/html.go pkg/auth/html/...

bindata-specs:
	go-bindata -pkg specs -o pkg/specs/specs.go swagger.yaml

bindata: bindata-views bindata-specs

# Runs the server
run:
	go run $(CMD_EXEC)/main \
	--tls-certificate $(CERTS_FOLDER)/cert.pem \
	--tls-key $(CERTS_FOLDER)/key.pem \
	--tls-port 20441 \
	--port 2080

# Compiles the app
compile-server:
	go build -o $(BIN_FOLDER)/server.exe $(CMD_EXEC)/main

compile: compile-server

# Tests the api specs against fake generated data
test_server:
	go test ./test --count 1

test: test_server

# Generates development tls certificates
tls:
	cd $(CERTS_FOLDER) && \
	go run "${GOROOT}/src/crypto/tls/generate_cert.go" \
	--host localhost \
	--ca