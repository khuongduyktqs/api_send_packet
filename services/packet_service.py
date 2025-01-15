import struct
import binascii
import socket
import json
import fcntl

# Constants
IF_NAME = "eth0"
ETHER_TYPE_IPV4 = 0x0800
DEFAULT_DEST_MAC = "00:0c:29:61:1f:25"
DEFAULT_DEST_IP = "192.168.23.142"
DEFAULT_DEST_PORT = 80
DEFAULT_SRC_PORT = 80
MTU_SIZE = 1500

# Create raw socket
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((IF_NAME, 0))


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def get_interface_info(ifname, sock):
    ifr = struct.pack('256s', ifname[:15].encode('utf-8'))
    mac_address = fcntl.ioctl(sock.fileno(), 0x8927, ifr)[18:24]
    ip_address = socket.inet_ntoa(
        fcntl.ioctl(sock.fileno(), 0x8915, ifr)[20:24])
    return mac_address, ip_address


def pad_ports(port_list, length=20):
    padded_ports = port_list[:]
    while len(padded_ports) < length:
        padded_ports.append(0)
    return padded_ports[:length]


src_mac, src_ip = get_interface_info(IF_NAME, sock)


def send_packet_logic(data):
    try:
        config_list = data["data"].get("config_list", [])
        port_lists = data["data"].get("port_lists", [])
        config = data["data"].get("config", {})

        # Map group_port keys to their port lists
        port_mapping = {item["key"]: item["port_lists"] for item in port_lists}

        # Fixed header values
        dest_mac = binascii.unhexlify(DEFAULT_DEST_MAC.replace(":", ""))
        dest_ip = socket.inet_aton(DEFAULT_DEST_IP)

        # Construct payload
        payload = bytearray()
        payload.extend([0x04, 0x86])

        # Status bytes
        mac_status = 0xFF if config.get("mac_status", False) else 0x00
        ip_status = 0xFF if config.get("ip_status", False) else 0x00
        port_status = 0xFF if config.get("port_status", False) else 0x00

        payload.extend([mac_status, ip_status, port_status])

        # 8 bytes padding
        payload.extend([0x00] * 8)

        # Process port lists
        for key, port_list in port_mapping.items():
            padded_ports = pad_ports(port_list)
            for port in padded_ports:
                payload.extend(struct.pack("!H", port))

        # Packet number logic
        num_packets = (
            len([c for c in config_list if c.get("status")]) - 1) // 100 + 1

        for packet_index in range(1, num_packets + 1):
            current_payload = bytearray(payload)
            current_payload.append(packet_index)

            for config_item in config_list[(packet_index - 1) * 100:packet_index * 100]:
                if config_item.get("status", False):
                    mac = binascii.unhexlify(
                        config_item["mac"].replace(":", ""))
                    ip = socket.inet_aton(config_item["ip"])
                    group_port = config_item.get("group_port", "")

                    # Append MAC and IP
                    current_payload.extend(mac)
                    current_payload.extend(ip)

                    # Append group_port bytes
                    if group_port == "one":
                        current_payload.extend([0xAA])
                    elif group_port == "two":
                        current_payload.extend([0xBB])
                    elif group_port == "three":
                        current_payload.extend([0xCC])
                    elif group_port == "four":
                        current_payload.extend([0xDD])
                    elif group_port == "five":
                        current_payload.extend([0xEE])                        
                    else:
                        current_payload.extend([0x00])

            # Pad remaining payload to MTU_SIZE
            if len(current_payload) > (MTU_SIZE - 14 - 20 - 20):  # Ethernet, IP, TCP headers
                raise ValueError("Payload size exceeds MTU")
            current_payload.extend(
                [0x00] * (MTU_SIZE - 14 - 20 - 20 - len(current_payload)))

            # Construct Ethernet header
            eth_header = struct.pack(
                "!6s6sH", dest_mac, src_mac, ETHER_TYPE_IPV4)

            # Construct IP header
            version_ihl = (4 << 4) + 5
            total_length = 20 + 20 + len(current_payload)
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                version_ihl, 0, total_length, 0, 0, 255, socket.IPPROTO_TCP, 0,
                socket.inet_aton(src_ip), dest_ip
            )
            ip_checksum = checksum(ip_header)
            ip_header = ip_header[:10] + \
                struct.pack('H', ip_checksum) + ip_header[12:]

            # Construct TCP header
            seq_num = 1
            data_offset = 5
            flags = 0b000010
            window = socket.htons(5840)
            pseudo_header = struct.pack(
                "!4s4sBBH", socket.inet_aton(
                    src_ip), dest_ip, 0, socket.IPPROTO_TCP, 20 + len(current_payload)
            )
            tcp_header = struct.pack(
                "!HHLLBBHHH",
                DEFAULT_SRC_PORT, DEFAULT_DEST_PORT, seq_num, 0,
                data_offset << 4, flags, window, 0, 0
            )
            tcp_checksum = checksum(
                pseudo_header + tcp_header + current_payload)
            tcp_header = tcp_header[:16] + \
                struct.pack('H', tcp_checksum) + tcp_header[18:]

            # Full packet
            packet = eth_header + ip_header + tcp_header + current_payload

            # Send the packet
            sock.send(packet)

        return "All packets sent successfully."

    except Exception as e:
        return {"message": f"Error: {str(e)}", "status": "error"}
