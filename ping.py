#!/usr/bin/env python
# coding: utf-8

"""
    A pure python ping implementation using raw sockets.

    Note that ICMP messages can only be send from processes running as root
    (in Windows, you must run this script as 'Administrator').

    Bugs are naturally mine. I'd be glad to hear about them. There are
    certainly word - size dependencies here.
    
    :homepage: https://github.com/jedie/python-ping/
    :copyleft: 1989-2011 by the python-ping team, see AUTHORS for more details.
    :license: GNU GPL v2, see LICENSE for more details.
"""


import os, sys, socket, struct, select, time, signal


if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time


# ICMP parameters

ICMP_ECHOREPLY = 0 # Echo reply (per RFC792)
ICMP_ECHO = 8 # Echo request (per RFC792)
ICMP_MAX_RECV = 2048 # Max size of incoming buffer

MAX_SLEEP = 1000

class PingStats:
    dest_ip = "0.0.0.0"
    send_count = 0
    receive_count = 0
    min_time = 999999999
    max_time = 0
    total_time = 0
    lost_count = 1.0

current_stats = PingStats # Used globally FIXME: Don't use global


def checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        sum = sum + (ord(hiByte) * 256 + ord(loByte))
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string): # Check for odd length
        loByte = source_string[len(source_string) - 1]
        sum += ord(loByte)

    sum &= 0xffffffff # Truncate sum to 32 bits (a variance from ping.c, which
                      # uses signed ints, but overflow is unlikely in ping)

    sum = (sum >> 16) + (sum & 0xffff)    # Add high 16 bits to low 16 bits
    sum += (sum >> 16)                    # Add carry from above (if any)
    answer = ~sum & 0xffff                # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer

class PingBase(object):
    def __init__(self, dest_ip):
        self.dest_ip = dest_ip


def do_one(dest_ip, deadline, seq_number, packet_size):
    """
    Returns either the delay (in ms) or None on deadline.
    """
    global current_stats

    delay = None

    try: # One could use UDP here, but it's obscure
        current_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except socket.error, (errno, msg):
        if errno == 1:
            # Operation not permitted - Add more information to traceback
            etype, evalue, etb = sys.exc_info()
            evalue = etype(
                "%s - Note that ICMP messages can only be send from processes running as root." % evalue
            )
            raise etype, evalue, etb

        print("failed. (socket error: '%s')" % msg)
        raise # raise the original error

    own_id = os.getpid() & 0xFFFF

    send_time = send_one_ping(current_socket, dest_ip, own_id, seq_number, packet_size)
    if send_time == None:
        current_socket.close()
        return delay

    current_stats.send_count += 1;

    receive_time, dataSize, ip_src_ip, icmp_seq_number, ip_ttl = receive_one_ping(current_socket, own_id, deadline)

    current_socket.close()

    if receive_time:
        delay = (receive_time - send_time) * 1000.0
        print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms" % (
            dataSize, socket.inet_ntoa(struct.pack("!I", ip_src_ip)), icmp_seq_number, ip_ttl, delay)
        )
        current_stats.receive_count += 1;
        current_stats.total_time += delay
        if current_stats.min_time > delay:
            current_stats.min_time = delay
        if current_stats.max_time < delay:
            current_stats.max_time = delay
    else:
        delay = None
        print("Request timed out.")

    return delay


def send_one_ping(current_socket, dest_ip, own_id, seq_number, packet_size):
    """
    Send one ping to the given >dest_ip<.
    """
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0

    # Make a dummy heder with a 0 checksum.
    header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, myChecksum, own_id, seq_number
    )

    padBytes = []
    startVal = 0x42
    for i in range(startVal, startVal + (packet_size)):
        padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
    data = bytes(padBytes)

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data) # Checksum is in network order

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, myChecksum, own_id, seq_number
    )

    packet = header + data

    sendTime = default_timer()

    try:
        current_socket.sendto(packet, (dest_ip, 1)) # Port number is irrelevant for ICMP
    except socket.error as e:
        print("General failure (%s)" % (e.args[1]))
        return

    return sendTime


def receive_one_ping(current_socket, own_id, deadline):
    """
    Receive the ping from the socket. deadline = in ms
    """
    timeout = deadline / 1000

    while True: # Loop while waiting for packet or deadline
        select_start = default_timer()
        inputready, outputready, exceptready = select.select([current_socket], [], [], timeout)
        select_duration = (default_timer() - select_start)
        if inputready == []: # deadline
            return None, 0, 0, 0, 0

        receive_time = default_timer()

        packet_data, address = current_socket.recvfrom(ICMP_MAX_RECV)

        ip_header = packet_data[:20]
        ip_version, ip_type, ip_length, \
        ip_id, ip_flags, ip_ttl, ip_protocol, \
        ip_checksum, ip_src_ip, ip_dest_ip = struct.unpack(
            "!BBHHHBBHII", ip_header
        )

        icmp_header = packet_data[20:28]
        icmp_type, icmp_code, icmp_checksum, \
        icmp_packet_id, icmp_seq_number = struct.unpack(
            "!BBHHH", icmp_header
        )

        if icmp_packet_id == own_id: # Our packet
            dataSize = len(packet_data) - 28
            return receive_time, dataSize, ip_src_ip, icmp_seq_number, ip_ttl

        timeout = timeout - select_duration
        if timeout <= 0:
            return None, 0, 0, 0, 0


def dump_stats():
    """
    Show stats when pings are done
    """
    global current_stats

    print("\n----%s PYTHON PING Statistics----" % (current_stats.dest_ip))

    if current_stats.send_count > 0:
        current_stats.lost_count = (current_stats.send_count - current_stats.receive_count) / current_stats.send_count

    print("%d packets transmitted, %d packets received, %0.1f%% packet loss" % (
        current_stats.send_count, current_stats.receive_count, 100.0 * current_stats.lost_count
    ))

    if current_stats.receive_count > 0:
        print("round-trip (ms)  min/avg/max = %0.3f/%0.3f/%0.3f" % (
            current_stats.min_time, current_stats.total_time / current_stats.receive_count, current_stats.max_time
        ))

    print("")


def signal_handler(signum, frame):
    """
    Handle exit via signals
    """
    dump_stats()
    print("\n(Terminated with signal %d)\n" % (signum))
    sys.exit(0)


def verbose_ping(hostname, deadline=1000, count=3, packet_size=55):
    """
    Send >count< ping to >dest_ip< with the given >deadline< and display
    the result.
    """
    global current_stats

    signal.signal(signal.SIGINT, signal_handler)   # Handle Ctrl-C
    if hasattr(signal, "SIGBREAK"):
        # Handle Ctrl-Break e.g. under Windows 
        signal.signal(signal.SIGBREAK, signal_handler)

    current_stats = PingStats() # Reset the stats

    seq_number = 0 # Starting value

    try:
        dest_ip = socket.gethostbyname(hostname)
        # FIXME: Use dest_ip only for display this line here? see: https://github.com/jedie/python-ping/issues/3
        print("\nPYTHON-PING %s (%s): %d data bytes" % (hostname, dest_ip, packet_size))
    except socket.gaierror as e:
        print("\nPYTHON-PING: Unknown host: %s (%s)" % (hostname, e.args[1]))
        print("")
        return

    current_stats.dest_ip = dest_ip

    for i in range(count):
        delay = do_one(dest_ip, deadline, seq_number, packet_size)

        if delay == None:
            delay = 0

        seq_number += 1

        # Pause for the remainder of the MAX_SLEEP period (if applicable)
        if (MAX_SLEEP > delay):
            time.sleep((MAX_SLEEP - delay) / 1000)

    dump_stats()


if __name__ == '__main__':
    # FIXME: Add a real CLI
    if len(sys.argv) == 1:
        print "DEMO"

        # These should work:
        verbose_ping("heise.de")
        verbose_ping("google.com")

        # Inconsistent on Windows w/ ActivePython (Python 3.2 resolves correctly
        # to the local host, but 2.7 tries to resolve to the local *gateway*)
        verbose_ping("localhost")

        # Should fail with 'getaddrinfo failed':
        verbose_ping("foobar_url.foobar")

        # Should fail (deadline), but it depends on the local network:
        verbose_ping("192.168.255.254")

        # Should fails with 'The requested address is not valid in its context':
        verbose_ping("0.0.0.0")
    elif len(sys.argv) == 2:
        verbose_ping(sys.argv[1])
    else:
        print "Error: call ./ping.py domain.tld"
