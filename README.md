# ISOLATED NODE

## Setup
git clone https://github.com/bitcoin/bitcoin.git
python scripts/generate_rpc_auth_conf.py
sudo ln -s /mnt/d/btc /mnt/data/btc

## Launch docker container
docker compose -f compose/docker_compose_isolated.yaml build --no-cache
docker compose -f compose/docker_compose_isolated.yaml up
docker compose -f compose/docker_compose_isolated.yaml down

## Enter to docker container
docker exec -it bitcoin-node-knots bash

## Run inside docker container
bitcoin-cli getpeerinfo
bitcoin-cli getnetworkinfo
bitcoin-cli getnetworkinfo | grep "connections"