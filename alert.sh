#!/bin/bash 

if zenity --question --text="<b>Deauth</b> Attacks Detected, Click OK for ignore, No for disconnect" --cancel-label="Cancel"; then
zenity --width=300 --width=200 --info --title='Info!' --text="Beware, you might connected to Rogue AP or in MiTM attack"
else
zenity --width=300 --width=200 --error --title='Hang On!' --text="Switching Off your Wireless Network" ; rfkill block all
fi
