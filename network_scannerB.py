#!/usr/bin/env python

from scapy.all import *
import scapy.all as scapy

def scan(ip):
    scapy.arping(ip)

scan("10.0.2.1/24")
