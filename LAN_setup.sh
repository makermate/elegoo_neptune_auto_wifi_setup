# Login into the printer on the same network:

ssh mks@10.65.2.2

# username: mks
# password: makerbase


sudo apt update
sudo apt install dnsmasq -y

# Edit the dnsmasq.conf file:
sudo nano /etc/dnsmasq.conf

# Add the following lines at the end of the file:

# Interface to listen on
interface=eth0
bind-interfaces

# DHCP range and lease time
dhcp-range=192.168.100.50,192.168.100.150,12h

# DNS servers to use
server=8.8.8.8
server=8.8.4.4

# Assign a Static IP to the Printer's Ethernet Interface
# Create or edit the network configuration file. Depending on your system, this could be:

sudo nano /etc/network/interfaces.d/eth0

# Add the following configuration:
auto eth0
iface eth0 inet static
    address 192.168.100.1
    netmask 255.255.255.0

# Restart Network Services
sudo systemctl restart networking
sudo systemctl restart dnsmasq


# Then you should be able to ping 192.168.100.1 from the connected device through ethernet

