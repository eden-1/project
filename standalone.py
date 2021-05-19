from scapy.all import *
import requests
import json
import ipaddress
import subprocess
IP_ADDRESS = "127.0.0.1"  # server ip address
PORT = 2000
ip_countries_dict = {}


class IpIsReserved(Exception):
	pass


class Error(Exception):
	pass


def my_ip():
	"""
	:return: the client's ip address
	:rtype: str
	"""
	full_msg = Ether() / IP(dst="8.8.8.8") / UDP(sport=8139, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.google.com"))
	return full_msg[IP].src


def is_good(check_packet):
	"""
	:param check_packet: packet information
	:return: whether a packet is suitable (tcp/ip or udp/ip)
	:rtype: bool
	"""""
	host = my_ip()
	if not (check_packet.haslayer(IP) and (check_packet.haslayer(UDP) or check_packet.haslayer(TCP))):
		return False
	if check_packet[IP].src == host:
		if ipaddress.ip_address(check_packet[IP].dst).is_private or ipaddress.ip_address(check_packet[IP].dst).is_reserved:
			return False
	elif check_packet[IP].dst == host:
		if ipaddress.ip_address(check_packet[IP].src).is_private or ipaddress.ip_address(check_packet[IP].src).is_reserved:
			return False
	else:
		return False
	return True


def sniff_packets():
	"""
	:return: 5 packets that are tcp/ip or udp/ip
	"""
	packets = sniff(count=10, lfilter=is_good)
	return packets


def ip_country(ip_address):
	"""

	:param ip_address: address to check its server location
	:return: country where the server is located
	"""
	url = "http://ip-api.com/json/" + ip_address + "?fields=status,message,country"
	response = requests.get(url)
	response_text = json.loads(response.text)
	if response_text["status"] == "success":
		return response_text["country"]
	else:
		raise IpIsReserved  # ip is a special reserved address so it doesn't have a server


def ip_conversation(host_ip, packet1):
	"""
	:param host_ip: host's ip address
	:param packet1: packet information
	:return: packet's conversation ip address (not the host's) and a boolean value that represents the packet state:
	True for packet coming in and False for packet coming out
	"""
	if host_ip == packet1[IP].src:
		return packet1[IP].dst, False
	elif host_ip == packet1[IP].dst:
		return packet1[IP].src, True
	else:
		raise Error


def port(packet1, coming_in):
	"""
	:param packet1: packet information
	:param coming_in: a boolean value: True  - if packet coming in, and False - if packet coming out
	:return: port conversation (not the host's)
	"""
	if packet1.haslayer(UDP):
		if coming_in:
			return packet1[UDP].sport
		else:
			return packet1[UDP].dport
	elif packet1.haslayer(TCP):
		if coming_in:
			return packet1[TCP].sport
		else:
			return packet1[TCP].dport
	else:
		raise Error


def get_programs_dict():
	"""
	:return: a dictionary contains open applications and their ips and ports
	"""
	my_out = subprocess.Popen('netstat -nb', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	stdout, stderr = my_out.communicate()
	info = stdout.decode().splitlines()[4:]
	ips_list = []
	programs_list = []
	for line in info:
		if "TIME_WAIT" in line:
			continue
		elif ":" in line:
			ips_list.append(line[-36:-12].strip())
		elif "]" in line:
			programs_list.append(line.strip(' []'))
	ipp_dict = {}
	if len(programs_list) != len(ips_list):
		raise Error
	for i in range(len(ips_list)):
		ipp_dict[ips_list[i]] = programs_list[i]
	return ipp_dict


def program(ip, port1, d):
	"""
	:param ip: ip address
	:param port1: port
	:param d: dictionary contains open applications and their ips and ports
	:return: the application that uses the ip and port parameters, or None if it's not belong to any
	"""
	string = ip + ':' + str(port1)
	if string in d:
		return d[string]
	return None  # The ip and port don't belong to application


def create_message(packet1, host_ip):
	"""
	:param packet1: packet information
	:param host_ip: host's ip address
	:return: tuple contains packet requested information
	"""
	global ip_countries_dict
	if packet1[IP].src != host_ip and packet1[IP].dst != host_ip:
		raise Error
	conv_ip, coming_in = ip_conversation(host_ip, packet1)
	# if ipaddress.ip_address(conv_ip).is_private or ipaddress.ip_address(conv_ip).is_reserved:
	# 	continue
	if conv_ip not in ip_countries_dict:
		try:
			country = ip_country(conv_ip)
		except IpIsReserved:
			return None
		ip_countries_dict[conv_ip] = country
	conv_port = port(packet1, coming_in)
	d = get_programs_dict()
	pro = program(conv_ip, conv_port, d)
	# MyProtocol: (<IP conversation>, <ip country>, <is packet coming>, <port>, <packet size (bytes)>, <app>)
	return conv_ip, ip_countries_dict[conv_ip], coming_in, conv_port, len(packet1), pro


def main():
	host_ip = my_ip()
	while True:
		packets_info = []
		print("Sniffing...")
		packets = sniff_packets()
		print("Processing packets' information...")
		for packet1 in packets:
			info = create_message(packet1, host_ip)
			if info is not None:
				packets_info.append(info)
		print("sending information to manager...")
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		server_address = (IP_ADDRESS, PORT)
		msg = json.dumps(packets_info)
		sock.sendto(msg.encode(), server_address)
		sock.close()
		print("sending completed")


if __name__ == '__main__':
	main()
