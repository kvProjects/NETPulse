from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    
    arp_request = ARP(pdst=ip_range)
    
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    arp_request_broadcast = broadcast / arp_request
    
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []

    for element in answered_list:
        device = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        devices.append(device)

    return devices


def display_results(results):

    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")

    for device in results:
        print(f"{device['ip']}\t\t{device['mac']}")


if __name__ == "__main__":

    target_network = "192.168.1.1/24"

    scan_result = scan_network(target_network)

    display_results(scan_result)
