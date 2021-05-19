import socket
import json
from bs4 import BeautifulSoup
import re
import time
SETTINGS_FILE_PATH = "settings.dat"
LISTEN_PORT = 2000


def get_workers_dict(file_path):
    """
    :param file_path: path where the settings are
    :return: dictionary contains workers names and ips
    """
    workers = [i.strip() for i in open(file_path).readlines()][0].split(" = ")[1].split(',')
    workers_dict = {}
    for worker in workers:
        workers_dict[worker.split(':')[1]] = worker.split(':')[0]
    return workers_dict


def get_blacklist_dict(file_path):
    """
    :param file_path: path where the settings are
    :return: dictionary contains blacklist ips
    """
    blacklist = [i.strip() for i in open(file_path).readlines()][1].split(" = ")[1].split(',')
    blacklist_dict = {}
    for address in blacklist:
        blacklist_dict[address.split(':')[1]] = address.split(':')[0]
    return blacklist_dict


# def replace_agents(name, din, dout, soup):
#     out_origin = soup.find(string=re.compile("%%AGENTS_OUT_KEYS%%"))
#     out_new = out_origin.replace("%%AGENTS_OUT_KEYS%%", str([name])).replace("%%AGENTS_OUT_VALUES%%", str([dout]))
#     out_origin.replace_with(BeautifulSoup(out_new, features="html.parser"))
#     in_origin = soup.find(string=re.compile("%%AGENTS_IN_KEYS%%"))
#     in_new = in_origin.replace("%%AGENTS_IN_KEYS%%", str([name])).replace("%%AGENTS_IN_VALUES%%", str([din]))
#     in_origin.replace_with(BeautifulSoup(in_new, features="html.parser"))
#     return soup
#
#
# def replace_time(soup):
#     localtime = BeautifulSoup("Last update: " + time.asctime(time.localtime(time.time())), features="html.parser")
#     soup.find(text=re.compile("Last update:")).replace_with(localtime)
#     return soup
#
#
# def replace_countries(countries, datas, soup):
#     origin = soup.find(string=re.compile("%%COUNTRIES_KEYS%%"))
#     new = origin.replace("%%COUNTRIES_KEYS%%", str(countries)).replace("%%COUNTRIES_VALUES%%", str(datas))
#     origin.replace_with(BeautifulSoup(new, features="html.parser"))
#     return soup
#
#
# def replace_ips(ips, datas, soup):
#     origin = soup.find(string=re.compile("%%IPS_KEYS%%"))
#     new = origin.replace("%%IPS_KEYS%%", str(ips)).replace("%%IPS_VALUES%%", str(datas))
#     origin.replace_with(BeautifulSoup(new, features="html.parser"))
#     return soup
#
#
# def replace_apps(apps, datas, soup):
#     origin = soup.find(string=re.compile("%%APPS_KEYS%%"))
#     new = origin.replace("%%APPS_KEYS%%", str(apps)).replace("%%APPS_VALUES%%", str(datas))
#     origin.replace_with(BeautifulSoup(new, features="html.parser"))
#     return soup
#
#
# def replace_ports(ports, datas, soup):
#     origin = soup.find(string=re.compile("%%PORTS_KEYS%%"))
#     new = origin.replace("%%PORTS_KEYS%%", str(ports)).replace("%%PORTS_VALUES%%", str(datas))
#     origin.replace_with(BeautifulSoup(new, features="html.parser"))
#     return soup
#
#
# def replace_alerts(name, alerts):
#     pass
#
#
# def save_html_five(file_path, packets, agent_name):
#     # MyProtocol: (<IP conversation>, <ip country>, <is packet coming>, <port>, <packet size (bytes)>, <app>)
#     with open("template/html/template.html") as fp:
#         soup = BeautifulSoup(fp, features="html.parser")
#     data_in = 0
#     data_out = 0
#     countries_list = []
#     cdatas_list = []
#     ips_list = []
#     idatas_list = []
#     apps_list = []
#     adatas_list = []
#     ports_list = []
#     pdatas_list = []
#     alerts_list = []
#     for packet in packets:
#         if packet[2]:
#             data_in += packet[4]
#         else:
#             data_out += packet[4]
#         if packet[1] in countries_list:
#             i = countries_list.index(packet[1])
#             cdatas_list[i] += packet[4]
#         else:
#             countries_list.append(packet[1])
#             cdatas_list.append(packet[4])
#         if packet[0] in ips_list:
#             i = ips_list.index(packet[0])
#             idatas_list[i] += packet[4]
#         else:
#             ips_list.append(packet[0])
#             idatas_list.append(packet[4])
#         if packet[5] in apps_list:
#             i = apps_list.index(packet[5])
#             adatas_list[i] += packet[4]
#         else:
#             apps_list.append(packet[5])
#             adatas_list.append(packet[4])
#         if packet[3] in ports_list:
#             i = ports_list.index(packet[3])
#             pdatas_list[i] += packet[4]
#         else:
#             ports_list.append(packet[3])
#             pdatas_list.append(packet[4])
#     soup = replace_agents(agent_name, data_in, data_out, soup)
#     soup = replace_time(soup)
#     soup = replace_countries(countries_list, cdatas_list, soup)
#     soup = replace_ips(ips_list, idatas_list, soup)
#     soup = replace_apps(apps_list, adatas_list, soup)
#     soup = replace_ports(ports_list, pdatas_list, soup)
#     with open(file_path, "w") as outf:
#         outf.write(str(soup))


def main():
    workers = get_workers_dict(SETTINGS_FILE_PATH)
    listening_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('', LISTEN_PORT)
    listening_sock.bind(server_address)
    print("listening started...")
    while True:
        (client_data, client_address) = listening_sock.recvfrom(1024)
        if client_address[0] in workers:
            print("message received from {0}:".format(workers[client_address[0]]))
            print(json.loads(client_data))
    listening_sock.close()


if __name__ == '__main__':
    main()
