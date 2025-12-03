import socket
import struct
import sys
import time

UPF_IP = "192.168.100.2"
UPF_PORT = 8805
LOCAL_IP = "192.168.100.1"

def build_pfcp_header(msg_type, length, seid=None, seq=1):
    version = 1
    s_flag = 1 if seid is not None else 0
    mp_flag = 0
    flags = (version << 5) | (s_flag << 0) | (mp_flag << 1)
    
    # Header: Flags(1), Type(1), Length(2)
    hdr = struct.pack("!BBH", flags, msg_type, length)
    if s_flag:
        hdr += struct.pack("!Q", seid)
    
    # Seq(3), Priority(1)
    # Seq is 3 bytes big endian.
    hdr += struct.pack("!I", seq)[1:] + b'\x00'
    return hdr

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOCAL_IP, 0))
    sock.settimeout(2.0)
    
    dest = (UPF_IP, UPF_PORT)
    
    print(f"Sending Association Setup Request to {dest}")
    # Association Setup Request (Type 5)
    # Node ID IE (Type 60): IPv4 192.168.100.1
    node_id_payload = b'\x00' + socket.inet_aton(LOCAL_IP) # Type 0 = IPv4
    node_id_ie = struct.pack("!HH", 60, 5) + node_id_payload
    
    payload = node_id_ie
    hdr = build_pfcp_header(5, len(payload) + 4, seq=1) # +4 for seq/prio
    sock.sendto(hdr + payload, dest)
    
    try:
        data, addr = sock.recvfrom(2048)
        print(f"Received {len(data)} bytes from {addr}")
        # Check type
        if data[1] == 6:
            print("Received Association Setup Response")
        else:
            print(f"Unexpected message type {data[1]}")
            sys.exit(1)
    except socket.timeout:
        print("Timeout waiting for Association Setup Response")
        sys.exit(1)

    print("Sending Session Establishment Request")
    # Session Establishment Request (Type 50)
    # Node ID: 192.168.100.1
    # F-SEID: IPv4 192.168.100.1, SEID 1
    fseid_payload = b'\x02' + struct.pack("!Q", 1) + socket.inet_aton(LOCAL_IP) # Flags 0x02=v4
    fseid_ie = struct.pack("!HH", 57, 13) + fseid_payload
    
    # Create PDR/FAR etc omitted for brevity, just minimal to get a response?
    # The UPF might reject if PDRs are missing.
    # Let's add a dummy Create PDR.
    # PDR ID 1
    pdr_id_ie = struct.pack("!HH", 56, 2) + struct.pack("!H", 1)
    # PDI
    # Source Interface: Access (0)
    si_ie = struct.pack("!HH", 20, 1) + b'\x00'
    pdi_payload = si_ie
    pdi_ie = struct.pack("!HH", 2, len(pdi_payload)) + pdi_payload
    
    create_pdr_payload = pdr_id_ie + pdi_ie
    create_pdr_ie = struct.pack("!HH", 1, len(create_pdr_payload)) + create_pdr_payload
    
    payload = node_id_ie + fseid_ie + create_pdr_ie
    hdr = build_pfcp_header(50, len(payload) + 4, seq=2)
    sock.sendto(hdr + payload, dest)
    
    upf_seid = 0
    try:
        data, addr = sock.recvfrom(2048)
        print(f"Received {len(data)} bytes from {addr}")
        if data[1] == 51:
            print("Received Session Establishment Response")
            # Extract SEID from F-SEID IE if present, or header?
            # Header SEID is the CP SEID (1).
            # We need the UPF SEID from the F-SEID IE in the payload.
            # Parse IEs...
            off = 16 # Header(4) + SEID(8) + Seq(4)
            while off < len(data):
                type = struct.unpack("!H", data[off:off+2])[0]
                length = struct.unpack("!H", data[off+2:off+4])[0]
                if type == 57: # F-SEID
                    # Flags(1), SEID(8)
                    upf_seid = struct.unpack("!Q", data[off+5:off+13])[0]
                    print(f"UPF SEID: {upf_seid}")
                off += 4 + length
        else:
            print(f"Unexpected message type {data[1]}")
            sys.exit(1)
    except socket.timeout:
        print("Timeout waiting for Session Establishment Response")
        sys.exit(1)

    if upf_seid == 0:
        print("Could not determine UPF SEID, assuming 1")
        upf_seid = 1

    print(f"Sending Session Modification Request (SEID={upf_seid})")
    # Session Modification Request (Type 52)
    # Header SEID should be UPF SEID.
    # Payload: minimal (maybe just Node ID?)
    payload = b'' # Empty payload is valid? Or maybe just Node ID?
    # Usually we update something. But empty might be accepted or ignored.
    # Let's send Node ID at least.
    # payload = node_id_ie
    
    hdr = build_pfcp_header(52, len(payload) + 4, seid=upf_seid, seq=3)
    sock.sendto(hdr + payload, dest)
    
    try:
        data, addr = sock.recvfrom(2048)
        print(f"Received {len(data)} bytes from {addr}")
        if data[1] == 53:
            print("Received Session Modification Response")
            print("SUCCESS: Session Modification handled")
        else:
            print(f"Unexpected message type {data[1]}")
            sys.exit(1)
    except socket.timeout:
        print("Timeout waiting for Session Modification Response")
        sys.exit(1)

if __name__ == "__main__":
    main()
