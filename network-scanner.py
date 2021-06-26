import scapy.all as scapy
import optparse


def get_arguments():
    arguments = optparse.OptionParser()
    arguments.add_option("-i", "--ip_address", metavar='\b', dest="target_ip", help= "give the specific target ip address")
    value, option = arguments.parse_args()
    if not value.target_ip:
        arguments.error("specify the target ip using -i or --ip_address")
    else:
        return value


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    brodcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = brodcast/arp_request
    answered_lst = scapy.srp(arp_packet, timeout=1, verbose=False)[0]
    return answered_lst


def extracting_values(answered_lst):
    client_lst = []
    for element in answered_lst:
        client_dict ={"IP": element[1].psrc, "MAC": element[1].hwsrc}
        client_lst.append(client_dict)
    return client_lst
# print(answered_lst.show())


def print_values(client_lst):
    print("Network-Scanner coded by @koushikk11\n")
    print("    IP\t\t\t   MAC-ADDRESS")
    print("-----------------------------------------")
    for i in range(0,len(client_lst)):
        print(client_lst[i]["IP"]+"\t\t"+client_lst[i]["MAC"])


value = get_arguments()
answered_lst = scan(value.target_ip)
client_lst = extracting_values(answered_lst)
print_values(client_lst)
