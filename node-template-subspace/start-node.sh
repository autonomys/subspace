#!/bin/bash

set -e

setup() {
    echo "Setting up docker Network, Volume, and Pulling Repo..."
    docker network create subspace || /bin/true
    docker volume create subspace-node-template || /bin/true
    docker pull subspacelabs/node-template-subspace
    echo "Setup/Update Complete."
}
run-full() {
    echo "Running Full Node..."
    docker run --rm --init -it \
    --net subspace \
    --name node-template-subspace-full \
    --mount source=node-template-subspace,target=/var/subspace \
    --publish 0.0.0.0:30333:30333 \
        --publish 127.0.0.1:9944:9944 \
        --publish 127.0.0.1:9933:9933 \
    subspacelabs/node-template-subspace \
        --dev \
        --base-path /var/subspace \
        --ws-external \
        --bootnodes /ip4/165.232.157.230/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp \
        --telemetry-url 'wss://telemetry.polkadot.io/submit/ 9'
}
killnode() {
    echo "Killing Node..."
    docker kill node-template-subspace-full
}
wipe() {
    echo "Wiping prior installation..."
    docker container kill node-template-subspace-full
    docker volume rm subspace-node-template
}
##
# Color  Variables
##
green='\e[32m'
blue='\e[34m'
clear='\e[0m'

##
# Color Functions
##

ColorGreen(){
echo -ne $green$1$clear
}
ColorBlue(){
echo -ne $blue$1$clear
}

menu(){
    echo -ne "
    ----------------------------------
                N O D E
    -=[Subspace - Subspace Testnet]=-
    ----------------------------------
    $(ColorGreen '1)') Setup/Update Node
    $(ColorGreen '2)') Run Full Node
    $(ColorGreen '3)') Kill Node
    $(ColorGreen '4)') Wipe Node
    $(ColorGreen '0)') Exit
    $(ColorBlue 'Choose an option:') $clear"

    read a
    case $a in
        1) setup ; menu ;;
        2) run-full ; menu ;;
        3) killnode ; menu ;;
        4) wipe ; menu ;;
        0) exit 0 ;;
        *) echo -e "Not a Valid Option, Try Again..."; menu;;
    esac
}
menu
