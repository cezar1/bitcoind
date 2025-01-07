# Isolated Bitcoin Node

Setup an isolated Bitcoin node using Docker and `bitcoind`. Follow these steps to clone, configure, and run the node. There are no binaries in this repo, all source code will be downloaded and compiled locally.

---


## Table of Contents
- [Setup](#setup)
- [Launch Docker Container](#launch-docker-container)
- [Enter Docker Container](#enter-docker-container)
- [Useful Bitcoin CLI Commands](#useful-bitcoin-cli-commands) 

---

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cezar1/bitcoind.git

2. **Generate the credentials that will be in .gitignore:**
   ```bash
   python scripts/generate_rpc_auth_conf.py

3. **Make the symbolic link for the btc folder**
    ```bash
    sudo ln -s /mnt/d/btc /mnt/data/btc

3. **Make the symbolic link for the btc folder**
    ```bash
    sudo ln -s /mnt/d/btc /mnt/data/btc
    ```

## Launch Docker Container

1. **Build the container** (--no-cache ensures fresh build):
    ```bash
    docker compose -f compose/docker_compose_isolated.yaml build --no-cache
    ```

2. **Start the container** (this will run your Bitcoin node):
    ```bash
    docker compose -f compose/docker_compose_isolated.yaml up
    ```

3. **Stop the container** (use this when you need to shut down):
    ```bash
    docker compose -f compose/docker_compose_isolated.yaml down
    ```

## Enter Docker Container

To access the running container's shell:
```bash
docker exec -it bitcoin-node-knots bash
```

## Useful Bitcoin CLI Commands

Once inside the container, you can run these commands to check your node's status:

```bash
# Get detailed information about connected peers
bitcoin-cli getpeerinfo

# View general network information
bitcoin-cli getnetworkinfo

# Check only the connection count
bitcoin-cli getnetworkinfo | grep "connections"
``` 