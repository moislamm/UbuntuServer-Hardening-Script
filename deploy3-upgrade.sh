#!/bin/bash

##############################################################
echo '===Performing update and system upgrades==============='
sudo apt-get update |ts
sudo apt-get upgrade -y |ts
echo '###DONE!###'
##############################################################
