APP_NAME=github.com/goolanger/swaggerize-auth

CERTS_FOLDER=data/certs
LOGS_FOLDER=data/logs
BIN_FOLDER=data/bin
CMD_EXEC=./cmd

# Init the project
init_module:
	go mod init $(APP_NAME)
	mkdir test

init: init_module

# Generates the swagger definitions given the specs
swagger:
	go run ./cmd/swagger

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
swaggerize: swagger api run

# Makes all external files to go binaries
bindata-authorization:
	go-bindata -pkg auth -o pkg/auth/html.go pkg/auth/html/...

# bindata
bindata: bindata-authorization run

# views generation
define generate-views
    cp -r pkg/auth/html/views/basic pkg/auth/html/views/$(1)
    cp -r pkg/auth/html/mail/basic pkg/auth/html/mail/$(1)
endef

VIEWS?=basic

views:
	$(call generate-views,$(VIEWS))

# Runs the server
run:
	go run $(CMD_EXEC)/main \
	--tls-certificate $(CERTS_FOLDER)/cert.pem \
	--tls-key $(CERTS_FOLDER)/key.pem \
	--tls-port 20443 \
	--port 2080

# Compiles the app
compile-server:
	go build -o $(BIN_FOLDER)/server.exe $(CMD_EXEC)/main

compile-desktop:
	go build -o $(BIN_FOLDER)/desktop.exe $(CMD_EXEC)/desktop

compile: compile-server compile-desktop

# Tests the api specs against fake generated data
test_server:
	go test ./test --count 1

test: test_server

# Creates the Mobile client definitions using the swagger specs
define generate-client
	docker run -t --rm -v ${PWD}:/local openapitools/openapi-generator-cli:v4.3.1 generate \
	--input-spec /local/swagger.yaml \
	--output /local/client/$(1)/openapi \
	--generator-name ts
endef

client:
	$(call generate-client,react/src)
	$(call generate-client,mobile)

# Generates development tls certificates
tls:
	cd $(CERTS_FOLDER) && \
	go run "${GOROOT}/src/crypto/tls/generate_cert.go" \
	--host localhost \
	--ca