runn this command pyinstaller --onefile --noconsole pdu_manger.py to bulid the exe file . 



PDU Manager – User Guide
Overview

The PDU Manager is a graphical interface for controlling your PDUs (Power Distribution Units) over SSH.
It allows you to store multiple PDU devices (with their IP, username, and password) and quickly connect to them to control outlet loads.

The tool simplifies the workflow by providing buttons for connecting, selecting outlets (loads), and sending commands (on force, off force, cycle force).
All commands and responses are logged in the console area for visibility.

Features

Store and manage multiple PDUs with different IPs.

Connect to a PDU using saved username/password.

Navigate the PDU menu (device → load xx).

Perform actions: On Force, Off Force, Cycle Force.

Return to device selection with End.

Console logs everything sent/received.


How to Use
1. Add a Device

Click Add Device.

Enter:

Name → Friendly name for the rack (e.g., Rack 1).

IP Address → Full IPv4 (example: 10.228.42.235).

Username → Enter localadmin (or the username required by your device).

Password → Enter the PDU’s login password.

Click Save. The device will appear on the left list.

2. Connect to a Device

Select the device from the left panel.

Click Connect.

The console will log:

[Connecting to Rack 1 (10.228.42.235)...]
[Connected successfully]


If login fails, check IP/username/password.

3. Enter Device Mode

After connecting, click the Device button.

The console will show the device command being sent.

4. Control Loads

Enter the outlet number in the Load # box (example: 12).

Click Load.

Console will log load 12.

Choose an action:

Off Force → Sends off force.

On Force → Sends on force.

Cycle Force → Sends cycle force.

Console shows all commands and responses.

5. Switch Between Loads

Click End to return to the device prompt.

Enter a new load number and repeat the steps.

Notes

Always use localadmin as the username unless your PDU requires a different one.

IPs must be full IPv4 addresses (e.g., 10.228.42.235).

If your PDU asks for confirmation and it’s not "yes", contact support so the program can be updated to auto-respond.

 author’s name: Ahmed Aldulaimi.

