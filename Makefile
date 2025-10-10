# SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

BIN_DIR := bin
APP := ion

.PHONY: all build test clean

all: build

build:
	@mkdir -p $(BIN_DIR)
	GO111MODULE=on CGO_ENABLED=0 go build -o $(BIN_DIR)/$(APP) ./cmd/ion

test:
	go test ./...

clean:
	rm -rf $(BIN_DIR)


