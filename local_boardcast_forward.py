import asyncio
import struct
import socket

# recieve data at port then forward to boardcast ip 127.255.255.255

LOOP_BOARDCAST_IP = "127.255.255.255"
LOOP_LOCAL_IP = "127.0.0.1"

RECV_LOCAL_IP = "10.0.0.1"
DISCOVERY_PORT = 4992

LogTemp = False
BoardcastTransport = None

def print_info(*args):
    global LogTemp
    if LogTemp:
        print()
        LogTemp = False

    print(*args)

def print_temp(*args):
    global LogTemp
    print(*args, end='\r')
    LogTemp = True


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, loop, handle_packet):
        self.loop = loop
        self.handle_packet = handle_packet

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.loop.create_task(self.handle_packet(self.transport, data, addr))


async def handle_discovery_packet(udp, data, addr):
    if addr[0] == LOOP_LOCAL_IP:
        return

    if len(data) >= 16:
        header = struct.unpack_from(">I", data, 0)[0]
        pkt_type = header >> 28
        oui = struct.unpack_from(">I", data, 8)[0] & 0xFFFFFF
        pkt_class_code = struct.unpack_from(">I", data, 12)[0] & 0xFFFF

        if oui == 7213 and pkt_type == 3 and pkt_class_code == 0xFFFF:
            await BoardcastTransport.sendto(data, (LOOP_BOARDCAST_IP, DISCOVERY_PORT))
            print_info(f"Forwarded packet from {addr[0]}:{addr[1]} to {LOOP_BOARDCAST_IP}:{DISCOVERY_PORT}")

async def main():
    global BoardcastTransport
    loop = asyncio.get_event_loop()

    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((LOOP_LOCAL_IP, DISCOVERY_PORT))
    sock.connect((LOOP_BOARDCAST_IP, DISCOVERY_PORT))
    BoardcastTransport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol,
        sock=sock
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((RECV_LOCAL_IP, DISCOVERY_PORT))

    return await loop.create_datagram_endpoint(
        lambda: UDPProtocol(loop, handle_discovery_packet),
        sock=sock
    )

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())
    loop.run_forever()