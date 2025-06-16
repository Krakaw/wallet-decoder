#!/bin/bash


BASE_URL="https://raw.githubusercontent.com/tari-project/tari/development/applications/minotari_app_grpc/proto/"
PROTO_FILES=(
    "base_node.proto"
    "block.proto"
    "network.proto"
    "p2pool.proto"
    "sidechain_types.proto"
    "transaction.proto"
    "types.proto"
    "validator_node.proto"
    "wallet.proto"
)

for FILE in "${PROTO_FILES[@]}"; do
  curl -sSLo "proto/$FILE" "$BASE_URL$FILE" && echo "Downloaded $FILE" || echo "Failed to download $FILE"
done