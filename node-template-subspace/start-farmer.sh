#!/bin/bash

set -e

setup() {
    echo "Setting up docker Network, Volume, and Pulling Repo..."
    docker network create subspace || /bin/true
    docker volume create subspace-farmer || /bin/true
    docker pull subspacelabs/subspace-farmer
    echo "Setup/Update Complete."
}

run-farm() {
    echo "Starting Farm..."
    docker run --rm --init -it \
    --net subspace \
    --name subspace-farmer \
    --mount source=subspace-farmer,target=/var/subspace \
    subspacelabs/subspace-farmer \
        farm \
        --ws-server ws://node-template-subspace-full:9944
}

plot-1gb() {
    echo "Plotting 1gb..."
    docker run --rm -it \
    --name subspace-farmer \
    --mount source=subspace-farmer,target=/var/subspace \
    subspacelabs/subspace-farmer plot 256000 subspace
}
wipe() {
    echo "Wiping prior installation..."
    docker container kill subspace-farmer
    docker volume rm subspace-farmer
}
erase() {
    echo "Erasing plot..."
    docker container kill subspace-farmer
    docker run --rm -it \
    --name subspace-farmer \
    --mount source=subspace-farmer,target=/var/subspace \
    subspacelabs/subspace-farmer erase-plot
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
                F A R M E R
    -=[Subspace - Subspace Testnet]=-
    ----------------------------------
    $(ColorGreen '1)') Setup/Update Farmer
    $(ColorGreen '2)') Plot 1GB of Data
    $(ColorGreen '3)') Run Farmer
    $(ColorGreen '4)') Wipe Farmer
    $(ColorGreen '5)') Erase Plot
    $(ColorGreen '0)') Exit
    $(ColorBlue 'Choose an option:') $clear"


    read a
    case $a in
        1) setup ; menu ;;
        2) plot-1gb ; menu ;;
        3) run-farm ; menu ;;
        4) wipe ; menu ;;
        5) erase ; menu ;;
        0) exit 0 ;;
        *) echo -e "Not a Valid Option, Try Again..."; menu;;
    esac
}
menu
