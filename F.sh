#!/bin/bash

# Check if tcping is already installed
if ! command -v tcping &> /dev/null; then
    echo "Installing tcping..."
    sudo apt-get update
    wget http://www.vanheusden.com/tcping/tcping-1.3.6.tar.gz
    tar -xvzf tcping-1.3.6.tar.gz
    cd tcping-1.3.6
    make
    sudo cp tcping /usr/local/bin/
    cd ..
    rm -rf tcping-1.3.6 tcping-1.3.6.tar.gz
    echo "tcping installed successfully!"
fi

# Perform a TCP ping
tcping 8.8.8.8 443
