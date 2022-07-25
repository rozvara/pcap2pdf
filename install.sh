#!/usr/bin/env bash
sudo install -d /usr/local/share/org.vync/flags
sudo install -m 644 flags/* /usr/local/share/org.vync/flags
sudo install -v -m 644 src/*.py /usr/local/share/org.vync
sudo install -v -m 644 src/*.conf /usr/local/share/org.vync
sudo install -v src/pcap2pdf /usr/local/bin
