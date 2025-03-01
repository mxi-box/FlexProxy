import asyncio
import struct
import re

# Configuration
FORWARD_IPS = ["10.0.0.255", "10.0.0.11", "10.0.0.15"] # IP Adresses that will receive the forwarded boradcast dicovery packets
NEW_IP = "10.0.0.17" # IP Address of the computer running this script, which will be used to communicate with the SmartSDR software
# NEW_IP = "10.0.0.1"
NEW_COMMAND_PORT = 4992 # Port of the computer running this script, which will be used to communicate with the SmartSDR software
FLEX_IP = "192.168.0.100" # IP Address of the FlexRadio device
# FLEX_IP = "127.0.0.2"

# Constants
COMMAND_PORT = 4992
FILE_PORT = 4995
DISCOVERY_PORT = 4992
VITA_PORT = 4991

UsingAddress = None
Local2FlexAddress = None

def print_info(*args):
    print(*args)

def print_temp(*args):
    print(*args, end='\r')

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, loop, handle_packet):
        self.loop = loop
        self.handle_packet = handle_packet

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.loop.create_task(self.handle_packet(self.transport, data, addr))

async def handle_discovery_packet(udp, data, addr):
    if addr[0] != FLEX_IP:
        return

    if len(data) >= 16:
        header = struct.unpack_from(">I", data, 0)[0]
        pkt_type = header >> 28
        oui = struct.unpack_from(">I", data, 8)[0] & 0xFFFFFF
        pkt_class_code = struct.unpack_from(">I", data, 12)[0] & 0xFFFF

        if oui == 7213 and pkt_type == 3 and pkt_class_code == 0xFFFF:
            payload_start = 16
            if header & 0x2000000:
                payload_start += 4
            if header & 0x1000000:
                payload_start += 8
            if (header >> 22) & 3 != 0:
                payload_start += 4
            if (header >> 20) & 3 != 0:
                payload_start += 8

            trail_length = 4 if header & 0x4000000 else 0
            
            payload = data[payload_start:len(data) - trail_length].decode('utf-8').strip('\x00')
            payload = payload.replace(f"ip={FLEX_IP}", f"ip={NEW_IP}")
            payload = payload.replace(f"port={COMMAND_PORT}", f"port={NEW_COMMAND_PORT}")
            if UsingAddress:
                payload = re.sub(r"inuse_(ip|host)=[^ ]+", f"inuse_\\1={UsingAddress}", payload)
            print_temp("Forwarding: ", payload)

            new_payload_bytes = payload.encode('utf-8')
            padding_length = (4 - (len(new_payload_bytes) % 4)) % 4
            new_payload_bytes += b'\x00' * padding_length

            new_data_length = payload_start + len(new_payload_bytes) + trail_length
            new_data = bytearray(new_data_length)
            new_data[:payload_start] = data[:payload_start]
            new_data[payload_start:payload_start + len(new_payload_bytes)] = new_payload_bytes
            if trail_length > 0:
                new_data[-trail_length:] = data[-trail_length:]

            new_packet_size = new_data_length // 4
            new_data[2:4] = struct.pack(">H", new_packet_size)
            
            for ip in FORWARD_IPS:
                udp.sendto(new_data, (ip, DISCOVERY_PORT))

async def handle_tcp_client(reader, writer):
    client_ip = writer.get_extra_info('peername')[0]
    loop = asyncio.get_running_loop()

    try:
        flex_reader, flex_writer = await asyncio.open_connection(FLEX_IP, COMMAND_PORT)
    except:
        writer.close()
        return

    reply_table = {}
    
    async def forward_to_flex():
        global UsingAddress
        client_vita_port = None
        is_ssdr = False
        async def shutdown_udp_forwarding():
            if client_vita_port:
                print_info("Closing UDP forwarding for", client_ip, "->", client_vita_port)
                del_udp_forwarding(client_ip, client_vita_port)

        try:
            while True:
                await flex_writer.drain()
                data = await reader.readline() 
                if not data:
                    break
                message = data.decode().strip()
                if match := re.match(r"C(\d+)\|client udpport (\d+)", message):
                    await shutdown_udp_forwarding()

                    client_vita_port = int(match.group(2))
                
                    local_vite_port = await setup_udp_forwarding(loop, client_ip, client_vita_port)
                    message = f"C{match.group(1)}|client udpport {local_vite_port}\n"
                    print_info("Opening UDP forwarding for", client_ip, ":", client_vita_port, "->", local_vite_port)
                    flex_writer.write(message.encode())
                    continue
                elif re.match(r"C\d?\|client program SmartSDR.*", message):
                    is_ssdr = True
                    UsingAddress = client_ip
                elif match := re.match(r"C(\d+)\|client ip", message):
                    reply_table[match.group(1)] = 1

                flex_writer.write(data)
        finally:
            if is_ssdr:
                UsingAddress = None
            await shutdown_udp_forwarding()

    async def forward_to_client():
        while True:
            await writer.drain()
            data = await flex_reader.readline()
            if not data:
                break
            message = data.decode().strip()
            if message[0] == 'S':
                idx = message.find('|')
                kvs = re.findall(r"([^= ]+)(=[^ ]+)?", message[idx+1:])
                statusType = kvs[0][0]
                if statusType == "audio_stream" or statusType == "mic_audio_stream" or statusType == "stream" or statusType == "tx_audio_stream" or statusType == "opus_stream":
                    ip, ipIdx, port, portIdx = None, None, None, None
                    for i, kv in enumerate(kvs):
                        if kv[0] == "ip" and len(kv[1]) > 0:
                            ip, ipIdx = kv[1][1:], i
                        elif kv[0] == "port" and len(kv[1]) > 0:
                            port, portIdx = int(kv[1][1:]), i
                    if ip and port:
                        cur_client_ip, cur_client_port = setup_udp_forwarding.port2client.get(port)
                        if cur_client_ip:
                            kvs[ipIdx] = ('ip', '=' + cur_client_ip)
                            kvs[portIdx] = ('port', '=' + str(cur_client_port))
                            message = message[:idx+1] + ' '.join([k[0] + k[1] for k in kvs]) + '\n'
                            writer.write(message.encode())
                            continue
            elif message[0] == 'R':
                if match := re.match(r"R(\d+)\|([0-9A-F]+)\|(.*)", message):
                    reply_id, reply_code, reply_str = match.groups()
                    reply = reply_table.get(reply_id)
                    if reply:
                        del reply_table[reply_id]
                    if reply == 1:
                        global Local2FlexAddress 
                        Local2FlexAddress = reply_str
                        message = f"R{reply_id}|{reply_code}|{client_ip}\n"
                        writer.write(message.encode())
                        continue
            elif message[0] == 'M':
                if match := re.match(r"M(\d+)\|Client connected from IP ", message):
                    message = f"M{match.group(1)}|Client connected from IP {client_ip}\n"
                    writer.write(message.encode())
                    continue

            writer.write(data)
                            

    forward_to_flex_task = loop.create_task(forward_to_flex())
    forward_to_client_task = loop.create_task(forward_to_client())

    await asyncio.wait([forward_to_flex_task, forward_to_client_task], return_when=asyncio.FIRST_COMPLETED)

    forward_to_flex_task.cancel()
    forward_to_client_task.cancel()

    flex_writer.close()
    writer.close()

VitaReceiver = None

async def init_vita_forwarding(loop):
    global VitaReceiver
    async def handle_vita_packet(udp, data, addr):
        transport = setup_udp_forwarding.transport.get((addr[0], addr[1]))
        if transport:
            transport.sendto(data, (FLEX_IP, VITA_PORT))

    VitaReceiver, _ = await loop.create_datagram_endpoint(
        lambda: UDPProtocol(loop, handle_vita_packet),
        local_addr=(NEW_IP, VITA_PORT),
    )


async def setup_udp_forwarding(loop, client_ip, client_vita_port):
    async def forward_udp_packet(udp, data, addr):
        if addr[0] == FLEX_IP:
            VitaReceiver.sendto(data, (client_ip, client_vita_port))
    
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPProtocol(loop, forward_udp_packet),
        local_addr=(Local2FlexAddress or '0.0.0.0', 0),
        # local_addr=('0.0.0.0', client_vita_port),
    )
    
    setup_udp_forwarding.transport[(client_ip, client_vita_port)] = transport
    
    port = transport.get_extra_info('sockname')[1]
    setup_udp_forwarding.port2client[port] = (client_ip, client_vita_port)

    return port

setup_udp_forwarding.transport = {} 
setup_udp_forwarding.port2client = {}

def del_udp_forwarding(client_ip, client_vita_port):
    transport = setup_udp_forwarding.transport.get((client_ip, client_vita_port))
    if transport:
        del setup_udp_forwarding.transport[(client_ip, client_vita_port)]
        port = transport.get_extra_info('sockname')[1]
        del setup_udp_forwarding.port2client[port]
        transport.close()

# !!! Untested !!!
async def setup_tcp_forwarding(loop, port):
    async def forward_tcp_packet(reader, writer):
        try:
            flex_reader, flex_writer = await asyncio.open_connection(FLEX_IP, port)
        except:
            writer.close()
            return

        async def forward_to_flex():
            while True:
                await flex_writer.drain()
                data = await reader.read(64*1024)
                if not data:
                    break
                flex_writer.write(data)

        async def forward_to_client():
            while True:
                await writer.drain()
                data = await flex_reader.read(64*1024)
                if not data:
                    break
                writer.write(data)

        forward_to_flex_task = loop.create_task(forward_to_flex())
        forward_to_client_task = loop.create_task(forward_to_client())

        await asyncio.wait([forward_to_flex_task, forward_to_client_task], return_when=asyncio.FIRST_COMPLETED)

        forward_to_flex_task.cancel()
        forward_to_client_task.cancel()

        flex_writer.close()
        writer.close()

    return await asyncio.start_server(forward_tcp_packet, NEW_IP, port)


async def main():
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPProtocol(loop, handle_discovery_packet),
        local_addr=('0.0.0.0', DISCOVERY_PORT)
    )

    tcp_command_server = await asyncio.start_server(handle_tcp_client, NEW_IP, NEW_COMMAND_PORT)
    tcp_file_server = await setup_tcp_forwarding(loop, FILE_PORT)
    await init_vita_forwarding(loop)
    await tcp_command_server.start_serving()
    await tcp_file_server.start_serving()
    return transport, tcp_command_server, tcp_file_server

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    transport, tcp_command_server, tcp_file_server = loop.run_until_complete(main())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        transport.close()
        tcp_command_server.close()
        tcp_file_server.close()
        VitaReceiver.close()
        loop.close()
        
