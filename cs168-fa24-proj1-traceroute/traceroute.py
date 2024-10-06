import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.version = int(b[0:4], 2)
        self.header_len = int(b[4:8], 2)*4
        self.tos = int(b[8:16], 2)
        self.length = int(b[16:32], 2)
        self.id = int(b[32:48], 2)
        self.flags = int(b[48:51], 2)
        self.frag_offset = int(b[51:64], 2)
        self.ttl = int(b[64:72], 2)
        self.proto = int(b[72:80], 2)
        self.cksum = int(b[80:96], 2)
        self.src = str(int(b[96:104], 2)) + '.' + str(int(b[104:112], 2)) + '.' + str(int(b[112:120], 2)) + '.' + str(int(b[120:128], 2))
        self.dst = str(int(b[128:136], 2)) + '.' + str(int(b[136:144], 2)) + '.' + str(int(b[144:152], 2)) + '.' + str(int(b[152:160], 2))

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.type = int(b[0:8], 2)
        self.code = int(b[8:16], 2)
        self.cksum = int(b[16:32], 2)

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.src_port = int(b[0:16], 2)
        self.dst_port = int(b[16:32], 2)
        self.len = int(b[32:48], 2)
        self.cksum = int(b[48:64], 2)

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like

def PacketDecoder(buffer: bytes):
    b = buffer.hex()
    ret = {}
    if len(b) < 40:
        return None
    ret["IPv4"] = IPv4(bytes.fromhex(b[0:40]))
    if len(b) < 2*ret["IPv4"].length:
        return None
    if ret["IPv4"].proto == 1:
        if len(b) < 2*ret["IPv4"].header_len + 32:
            return None
        ret["ICMP"] = ICMP(bytes.fromhex(b[2*ret["IPv4"].header_len : 2*ret["IPv4"].header_len + 32]))
        if ret["ICMP"].type != 3 and ret["ICMP"].type != 11:
            return None
        if ret["ICMP"].type == 11 and ret["ICMP"].code != 0:
            return None
        ret["Payload"] = PacketDecoder_2(bytes.fromhex(b[2*ret["IPv4"].header_len + 32:]))
    else:
        return None
    return ret
def PacketDecoder_2(buffer: bytes):
    b = buffer.hex()
    ret = {}
    if len(b) < 40:
        return None
    ret["IPv4"] = IPv4(bytes.fromhex(b[0:40]))
    if len(b) < 2*ret["IPv4"].length:
        return None
    if ret["IPv4"].proto == 1:
        if len(b) < 2*ret["IPv4"].header_len + 32:
            return None
        ret["ICMP"] = ICMP(bytes.fromhex(b[2*ret["IPv4"].header_len : 2*ret["IPv4"].header_len + 32]))
        if ret["ICMP"].type != 3 and ret["ICMP"].type != 11:
            return None
        if ret["ICMP"].type == 11 and ret["ICMP"].code != 0:
            return None
        ret["Payload"] = PacketDecoder(bytes.fromhex(b[2*ret["IPv4"].header_len + 32:]))
        if ret["Payload"] == False:
            return None
    else:
        if ret["IPv4"].proto == 17:
            if len(b) < 2*ret["IPv4"].header_len + 32:
                return None
            ret["UDP"] = UDP(bytes.fromhex(b[2*ret["IPv4"].header_len : 2*ret["IPv4"].header_len + 32]))
            ret["Payload"] = b[2*ret["IPv4"].header_len + 32:]
        else:
            return None
    return ret

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Add your implementation
    result = []
    address = '0'
    for ttl in range(1, TRACEROUTE_MAX_TTL+1):
        r = []
        sendsock.set_ttl(ttl)
        for attempt in range(1, PROBE_ATTEMPT_COUNT+1):
            pkg = "potato"
            sendsock.sendto(pkg.encode(), (ip, TRACEROUTE_PORT_NUMBER))
            if recvsock.recv_select():  # Check if there's a packet to process.
                buf, address = recvsock.recvfrom()  # Receive the packet.
                while len(result) != 0 and address[0] in result[len(result)-1] and recvsock.recv_select():
                    buf, address = recvsock.recvfrom()
                #print(f"\n{buf.hex()}\n");
                if address[0] in r:
                    continue
                decoded = PacketDecoder(buf)
                if decoded is None:
                    continue
                if decoded["Payload"] and decoded["Payload"]["Payload"] and decoded["Payload"]["Payload"] != pkg.encode().hex():
                    continue
                if decoded["IPv4"] and decoded["IPv4"].src != address[0]:
                    continue
                r.append(address[0])
        result.append(r)
        util.print_result(r, ttl)
        if address[0] == ip:
            break
    return result
    #sendsock.set_ttl(1)
    #sendsock.sendto("p".encode(),(ip,100))
    #if recvsock.recv_select():  # Check if there's a packet to process.
    #    buf, address = recvsock.recvfrom()  # Receive the packet.
    #print(f"{buf.hex()}")
    #print(f"Packet is from IP: {address[0]}")
    #print(f"Packet is from port: {address[1]}")

if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
