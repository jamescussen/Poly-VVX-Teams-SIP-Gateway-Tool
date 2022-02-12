# Poly-VVX-Teams-SIP-Gateway-Tool
A swiss army knife for your Poly VVXs and the Microsoft Teams SIP Gateway.

This tool allows you to remotely provision Poly VVX phones for Microsoft Teams SIP Gateway! Remote bulk Provisioning, Status checking, Sign-in, Sign-out, Restart and Password Changes. You can read all about it and how to use it on my blog here: https://www.myteamslab.com/2022/02/poly-vvx-teams-sip-gateway-tool.html

<p align="center">
  <img src="https://github.com/jamescussen/Poly-VVX-Teams-SIP-Gateway-Tool/raw/main/PolyVVXTeamsSIPGatewayTool.png" alt="Tool Image"/>
</p>

**Features:**

* GUI and command line execution modes. To use the GUI just run the tool without the "-Command" flag. to use command line mode run the tool using the "-Command" flag. See the command line flags section of the blog post for more details.
* Connect to individual IP Addresses or Ranges of IP Addresses using the IP list capability.
* Remotely connect to phones and do initial provisioning without having to log into the web interface manually.
* Remotely check the status of phones to see if they are provisioned, signed-in or signed-out.
* Remotely Sign-in the VVX phone to Microsoft Teams by clicking the "Teams Sign In" button. The tool will make the request for a Pairing Code and then you can complete the sign in through a browser. Once this process is completed, the phone will auto-reboot and sign into Teams (this includes provisioning reboots from Microsoft and takes about 5 mins).
Remotely Sign-out the VVX phone to Microsoft Teams by clicking the "Teams Sign Out" button. This will Sign Out the phone and have it reboot automatically back to the logged out state.
* Change the password used by phones to harden the security of the device. This is important because using defaults will leave your devices SIP registration credentials open to be stolen.
* Remotely restart VVX phones by clicking the "Reboot" button. There shouldn’t be many occasions when you need to do this. However, if something doesn’t seem to be working a reboot will get the phone to run through it’s provisioning again which may fix your problem.
* Import CSV of device IP Addresses. The CSV file only requires 1 column with a header column named "IPAddress". The CSV format that is exported from the Results Dialog can also be directly imported.
