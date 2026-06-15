#!/bin/bash

echo "--------------------"

iwlist "$1" channel | grep "Current"

echo "--------------------"

echo "Available Channels:"

iwlist "$1" channel | head -n -2

