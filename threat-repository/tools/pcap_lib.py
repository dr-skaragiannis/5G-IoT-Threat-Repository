"""
pcap_lib.py -- dependency-free reader for the NITRO 5G exercise captures.

The captures were taken with `tcpdump -i any`, which on modern libpcap yields
LINKTYPE_LINUX_SLL2 (276).  This module walks the pcap record-by-record and
decodes just enough of each frame (SLL2 -> IPv4/IPv6 -> TCP/UDP/SCTP/ICMP ->
5G application protocols) to support evidence extraction.  No external
dependencies, so it runs anywhere Python 3 runs.

Protocols recognised on top of L4:
  GTP-U    UDP/2152   user-plane tunnel (N3 gNB<->UPF)
  PFCP     UDP/8805   N4 SMF<->UPF session management
  NGAP     SCTP PPID 60 / port 38412   N2 gNB<->AMF
  HTTP/2   TCP SBI ports (7777, 8000, 80, 8080, 3000, 9090)
  MongoDB  TCP/27017  subscriber database (UDM/UDR backing store)
  DNS      UDP/53
"""

import struct
import os

# ---------------------------------------------------------------- constants

LINKTYPE_LINUX_SLL2 = 276
LINKTYPE_LINUX_SLL = 113
LINKTYPE_ETHERNET = 1

IPPROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 132: "SCTP", 58: "ICMPv6", 2: "IGMP"}

# SCTP chunk types (RFC 4960)
SCTP_CHUNK = {
    0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT",
    5: "HEARTBEAT_ACK", 6: "ABORT", 7: "SHUTDOWN", 8: "SHUTDOWN_ACK",
    9: "ERROR", 10: "COOKIE_ECHO", 11: "COOKIE_ACK", 12: "ECNE", 13: "CWR",
    14: "SHUTDOWN_COMPLETE",
}

# NGAP procedure codes (3GPP TS 38.413)
NGAP_PROC = {
    0: "AMFConfigurationUpdate", 1: "AMFStatusIndication",
    2: "CellTrafficTrace", 3: "DeactivateTrace",
    4: "DownlinkNASTransport", 5: "DownlinkNonUEAssociatedNRPPaTransport",
    6: "DownlinkRANConfigurationTransfer", 7: "DownlinkRANStatusTransfer",
    8: "DownlinkUEAssociatedNRPPaTransport", 9: "ErrorIndication",
    10: "HandoverCancel", 11: "HandoverNotification", 12: "HandoverPreparation",
    13: "HandoverResourceAllocation", 14: "InitialContextSetup",
    15: "InitialUEMessage", 16: "LocationReport",
    17: "LocationReportingControl", 18: "LocationReportingFailureIndication",
    19: "NASNonDeliveryIndication", 20: "NGReset", 21: "NGSetup",
    22: "OverloadStart", 23: "OverloadStop", 24: "Paging",
    25: "PathSwitchRequest", 26: "PDUSessionResourceModify",
    27: "PDUSessionResourceModifyIndication", 28: "PDUSessionResourceRelease",
    29: "PDUSessionResourceSetup", 30: "PDUSessionResourceNotify",
    31: "PrivateMessage", 32: "PWSCancel", 33: "PWSFailureIndication",
    34: "PWSRestartIndication", 35: "RANConfigurationUpdate",
    36: "RerouteNASRequest", 37: "RRCInactiveTransitionReport",
    38: "TraceFailureIndication", 39: "TraceStart",
    40: "UEContextModification", 41: "UEContextRelease",
    42: "UEContextReleaseRequest", 43: "UERadioCapabilityCheck",
    44: "UERadioCapabilityInfoIndication", 45: "UETNLABindingRelease",
    46: "UplinkNASTransport", 47: "UplinkNonUEAssociatedNRPPaTransport",
    48: "UplinkRANConfigurationTransfer", 49: "UplinkRANStatusTransfer",
    50: "UplinkUEAssociatedNRPPaTransport", 51: "WriteReplaceWarning",
    52: "SecondaryRATDataUsageReport",
}

NGAP_PDU_TYPE = {0: "initiatingMessage", 1: "successfulOutcome", 2: "unsuccessfulOutcome"}

# PFCP message types (3GPP TS 29.244 table 7.3-1)
PFCP_MSG = {
    1: "HeartbeatRequest", 2: "HeartbeatResponse",
    3: "PFDManagementRequest", 4: "PFDManagementResponse",
    5: "AssociationSetupRequest", 6: "AssociationSetupResponse",
    7: "AssociationUpdateRequest", 8: "AssociationUpdateResponse",
    9: "AssociationReleaseRequest", 10: "AssociationReleaseResponse",
    11: "VersionNotSupportedResponse", 12: "NodeReportRequest",
    13: "NodeReportResponse", 14: "SessionSetDeletionRequest",
    15: "SessionSetDeletionResponse",
    50: "SessionEstablishmentRequest", 51: "SessionEstablishmentResponse",
    52: "SessionModificationRequest", 53: "SessionModificationResponse",
    54: "SessionDeletionRequest", 55: "SessionDeletionResponse",
    56: "SessionReportRequest", 57: "SessionReportResponse",
}

# PFCP Cause values (TS 29.244 8.2.1)
PFCP_CAUSE = {
    1: "RequestAccepted", 64: "RequestRejected", 65: "SessionContextNotFound",
    66: "MandatoryIEMissing", 67: "ConditionalIEMissing",
    68: "InvalidLength", 69: "MandatoryIEIncorrect",
    70: "InvalidForwardingPolicy", 71: "InvalidFTEIDAllocationOption",
    72: "NoEstablishedPFCPAssociation", 73: "RuleCreationModificationFailure",
    74: "PFCPEntityInCongestion", 75: "NoResourcesAvailable",
    76: "ServiceNotSupported", 77: "SystemFailure", 78: "RedirectionRequested",
}

GTP_MSG = {
    1: "EchoRequest", 2: "EchoResponse", 26: "ErrorIndication",
    31: "SupportedExtensionHeadersNotification", 254: "EndMarker",
    255: "G-PDU",
}

ICMP_TYPE = {0: "EchoReply", 3: "DestUnreachable", 8: "EchoRequest",
             11: "TimeExceeded", 5: "Redirect"}

SBI_PORTS = {7777, 8000, 80, 8080, 3000, 9090, 29510, 29502, 29518}


def ip4(b):
    return "%d.%d.%d.%d" % tuple(b)


def ip6(b):
    return ":".join("%02x%02x" % (b[i], b[i + 1]) for i in range(0, 16, 2))


class Packet(dict):
    """A decoded frame.  Behaves as a dict; keys documented in decode()."""
    __getattr__ = dict.get


def _decode_sctp(data, pkt):
    """Walk the SCTP common header + chunk list."""
    if len(data) < 12:
        return
    sport, dport, vtag, cksum = struct.unpack(">HHII", data[:12])
    pkt["sport"], pkt["dport"] = sport, dport
    pkt["sctp_vtag"] = vtag
    chunks = []
    off = 12
    while off + 4 <= len(data):
        ctype, cflags, clen = struct.unpack(">BBH", data[off:off + 4])
        if clen < 4:
            break
        name = SCTP_CHUNK.get(ctype, "chunk%d" % ctype)
        chunks.append(name)
        if ctype == 0 and off + 16 <= len(data):  # DATA
            tsn, sid, ssn, ppid = struct.unpack(">IHHI", data[off + 4:off + 16])
            pkt["sctp_ppid"] = ppid
            pkt["sctp_tsn"] = tsn
            pkt["sctp_stream"] = sid
            payload = data[off + 16: off + clen]
            if ppid == 60:  # NGAP
                pkt["app"] = "NGAP"
                _decode_ngap(payload, pkt)
            elif ppid == 0 and payload:
                # ppid 0 == unspecified; the NITRO lab replay tool emits this
                pkt["app"] = "SCTP-DATA"
                _decode_ngap(payload, pkt)
            pkt["l5"] = payload
        off += (clen + 3) & ~3
    pkt["sctp_chunks"] = chunks


def _decode_ngap(p, pkt):
    """Minimal NGAP APER header decode: pduType + procedureCode."""
    if len(p) < 2:
        return
    pdu_type = p[0] & 0x7F
    # for the three NGAP PDU choices the first octet is 0x00/0x20/0x40
    choice = p[0] >> 5
    if choice in NGAP_PDU_TYPE and len(p) >= 2:
        pkt["ngap_pdu"] = NGAP_PDU_TYPE[choice]
        proc = p[1]
        pkt["ngap_proc_code"] = proc
        pkt["ngap_proc"] = NGAP_PROC.get(proc, "proc%d" % proc)


def _decode_pfcp(p, pkt):
    """PFCP header (TS 29.244 7.2)."""
    if len(p) < 8:
        return
    flags = p[0]
    version = flags >> 5
    s_flag = flags & 0x01
    mp_flag = (flags >> 1) & 0x01
    msg_type = p[1]
    length = struct.unpack(">H", p[2:4])[0]
    pkt["app"] = "PFCP"
    pkt["pfcp_version"] = version
    pkt["pfcp_msg_type"] = msg_type
    pkt["pfcp_msg"] = PFCP_MSG.get(msg_type, "msg%d" % msg_type)
    pkt["pfcp_len"] = length
    off = 4
    if s_flag:
        if len(p) >= 12:
            pkt["pfcp_seid"] = struct.unpack(">Q", p[4:12])[0]
        off = 12
    else:
        off = 8
    if len(p) >= off + 3:
        pkt["pfcp_seq"] = int.from_bytes(p[off - 4:off - 1], "big") if s_flag else \
            int.from_bytes(p[4:7], "big")
    # walk IEs looking for Cause and F-SEID
    ies = []
    i = off
    body = p
    while i + 4 <= len(body):
        ie_type, ie_len = struct.unpack(">HH", body[i:i + 4])
        val = body[i + 4:i + 4 + ie_len]
        ies.append((ie_type, ie_len))
        if ie_type == 19 and ie_len >= 1:  # Cause
            pkt["pfcp_cause"] = PFCP_CAUSE.get(val[0], "cause%d" % val[0])
        if ie_type == 57 and ie_len >= 9:  # F-SEID
            pkt["pfcp_fseid"] = struct.unpack(">Q", val[1:9])[0]
            if val[0] & 0x02 and ie_len >= 13:
                pkt["pfcp_fseid_ip"] = ip4(val[9:13])
        if ie_type == 60 and ie_len >= 1:  # Node ID
            if val[0] & 0x0F == 0 and ie_len >= 5:
                pkt["pfcp_nodeid"] = ip4(val[1:5])
        if ie_type == 21 and ie_len >= 9:  # F-TEID
            pkt["pfcp_teid"] = struct.unpack(">I", val[1:5])[0]
        i += 4 + ie_len
    pkt["pfcp_ies"] = ies


def _decode_gtpu(p, pkt):
    """GTP-U header (TS 29.281)."""
    if len(p) < 8:
        return
    flags = p[0]
    version = flags >> 5
    msg_type = p[1]
    length = struct.unpack(">H", p[2:4])[0]
    teid = struct.unpack(">I", p[4:8])[0]
    pkt["app"] = "GTP-U"
    pkt["gtp_version"] = version
    pkt["gtp_msg_type"] = msg_type
    pkt["gtp_msg"] = GTP_MSG.get(msg_type, "msg%d" % msg_type)
    pkt["gtp_teid"] = teid
    off = 8
    if flags & 0x07:
        off = 12
        nh = p[11] if len(p) > 11 else 0
        while nh and off < len(p):
            ext_len = p[off] * 4
            if ext_len == 0:
                break
            nh = p[off + ext_len - 1] if off + ext_len - 1 < len(p) else 0
            off += ext_len
    inner = p[off:]
    if msg_type == 255 and len(inner) >= 20 and (inner[0] >> 4) == 4:
        # inner IPv4
        ihl = (inner[0] & 0x0F) * 4
        proto = inner[9]
        pkt["gtp_inner_src"] = ip4(inner[12:16])
        pkt["gtp_inner_dst"] = ip4(inner[16:20])
        pkt["gtp_inner_proto"] = IPPROTO.get(proto, str(proto))
        if proto == 1 and len(inner) >= ihl + 8:
            ic = inner[ihl:]
            pkt["gtp_inner_icmp_type"] = ic[0]
            pkt["gtp_inner_icmp_name"] = ICMP_TYPE.get(ic[0], "type%d" % ic[0])
            pkt["gtp_inner_icmp_id"] = struct.unpack(">H", ic[4:6])[0]
            pkt["gtp_inner_icmp_seq"] = struct.unpack(">H", ic[6:8])[0]
        pkt["gtp_inner_len"] = struct.unpack(">H", inner[2:4])[0]


def _decode_l4(proto, data, pkt):
    pkt["proto"] = IPPROTO.get(proto, str(proto))
    if proto == 6 and len(data) >= 20:  # TCP
        sport, dport, seq, ack, offres, flags, win = struct.unpack(">HHIIBBH", data[:16])
        doff = (offres >> 4) * 4
        pkt["sport"], pkt["dport"] = sport, dport
        pkt["tcp_flags"] = flags
        pkt["tcp_seq"], pkt["tcp_ack"] = seq, ack
        pkt["tcp_win"] = win
        fl = ""
        for bit, ch in ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
                        (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C")):
            if flags & bit:
                fl += ch
        pkt["tcp_flagstr"] = fl
        payload = data[doff:]
        pkt["l5"] = payload
        if payload:
            if sport in SBI_PORTS or dport in SBI_PORTS:
                if payload[:3] == b"PRI" or (len(payload) >= 9 and payload[3] in (0, 1, 4, 6, 8)):
                    pkt["app"] = "HTTP2-SBI"
            if sport == 27017 or dport == 27017:
                pkt["app"] = "MongoDB"
            if payload[:4] in (b"GET ", b"POST", b"HTTP", b"PUT ", b"HEAD"):
                pkt["app"] = "HTTP"
    elif proto == 17 and len(data) >= 8:  # UDP
        sport, dport, ulen, cks = struct.unpack(">HHHH", data[:8])
        pkt["sport"], pkt["dport"] = sport, dport
        payload = data[8:]
        pkt["l5"] = payload
        if sport == 2152 or dport == 2152:
            _decode_gtpu(payload, pkt)
        elif sport == 8805 or dport == 8805:
            _decode_pfcp(payload, pkt)
        elif sport == 53 or dport == 53:
            pkt["app"] = "DNS"
        elif sport == 5353 or dport == 5353:
            pkt["app"] = "mDNS"
    elif proto == 132:  # SCTP
        _decode_sctp(data, pkt)
    elif proto == 1 and len(data) >= 8:  # ICMP
        pkt["icmp_type"] = data[0]
        pkt["icmp_code"] = data[1]
        pkt["icmp_name"] = ICMP_TYPE.get(data[0], "type%d" % data[0])
        pkt["icmp_id"] = struct.unpack(">H", data[4:6])[0]
        pkt["icmp_seq"] = struct.unpack(">H", data[6:8])[0]
        pkt["app"] = "ICMP"
        pkt["l5"] = data[8:]


def decode_frame(buf, linktype):
    """Decode one frame; returns a Packet dict (possibly with only l2 info)."""
    pkt = Packet()
    pkt["framelen"] = len(buf)
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(buf) < 20:
            return pkt
        etype, _mbz, ifindex, arphrd, ptype, halen = struct.unpack(">HHIHBB", buf[:12])
        pkt["ifindex"] = ifindex
        pkt["sll_pkttype"] = ptype
        pkt["ethertype"] = etype
        data = buf[20:]
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(buf) < 16:
            return pkt
        ptype, arphrd, halen = struct.unpack(">HHH", buf[:6])
        etype = struct.unpack(">H", buf[14:16])[0]
        pkt["ethertype"] = etype
        pkt["sll_pkttype"] = ptype
        data = buf[16:]
    elif linktype == LINKTYPE_ETHERNET:
        if len(buf) < 14:
            return pkt
        etype = struct.unpack(">H", buf[12:14])[0]
        pkt["ethertype"] = etype
        data = buf[14:]
    else:
        return pkt

    if etype == 0x0800 and len(data) >= 20:  # IPv4
        ver_ihl = data[0]
        ihl = (ver_ihl & 0x0F) * 4
        total_len = struct.unpack(">H", data[2:4])[0]
        ipid = struct.unpack(">H", data[4:6])[0]
        frag = struct.unpack(">H", data[6:8])[0]
        ttl = data[8]
        proto = data[9]
        pkt["ip_v"] = 4
        pkt["src"] = ip4(data[12:16])
        pkt["dst"] = ip4(data[16:20])
        pkt["ttl"] = ttl
        pkt["ip_len"] = total_len
        pkt["ip_id"] = ipid
        pkt["ip_proto_num"] = proto
        _decode_l4(proto, data[ihl:total_len if total_len else None], pkt)
    elif etype == 0x86DD and len(data) >= 40:  # IPv6
        pkt["ip_v"] = 6
        pkt["src"] = ip6(data[8:24])
        pkt["dst"] = ip6(data[24:40])
        nh = data[6]
        pkt["ip_proto_num"] = nh
        pkt["ttl"] = data[7]
        _decode_l4(nh, data[40:], pkt)
    elif etype == 0x0806:
        pkt["proto"] = "ARP"
        pkt["app"] = "ARP"
        if len(data) >= 28:
            pkt["arp_op"] = struct.unpack(">H", data[6:8])[0]
            pkt["arp_spa"] = ip4(data[14:18])
            pkt["arp_tpa"] = ip4(data[24:28])
    return pkt


def read_pcap(path, limit=None, want_raw=False):
    """Yield (frame_no, ts_epoch_float, Packet).  Streaming, low memory."""
    with open(path, "rb") as fh:
        gh = fh.read(24)
        magic = struct.unpack("<I", gh[:4])[0]
        if magic == 0xA1B2C3D4:
            endian, nano = "<", False
        elif magic == 0xD4C3B2A1:
            endian, nano = ">", False
        elif magic == 0xA1B23C4D:
            endian, nano = "<", True
        elif magic == 0x4D3CB2A1:
            endian, nano = ">", True
        else:
            raise ValueError("not a pcap: %s" % path)
        _, vmaj, vmin, tz, sig, snap, linktype = struct.unpack(endian + "IHHiIII", gh)
        rh = struct.Struct(endian + "IIII")
        n = 0
        read = fh.read
        while True:
            h = read(16)
            if len(h) < 16:
                break
            ts_s, ts_f, incl, orig = rh.unpack(h)
            body = read(incl)
            if len(body) < incl:
                break
            n += 1
            ts = ts_s + (ts_f / 1e9 if nano else ts_f / 1e6)
            pkt = decode_frame(body, linktype)
            pkt["origlen"] = orig
            if want_raw:
                pkt["raw"] = body
            yield n, ts, pkt
            if limit and n >= limit:
                break


def pcap_linktype(path):
    with open(path, "rb") as fh:
        gh = fh.read(24)
    magic = struct.unpack("<I", gh[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    return struct.unpack(endian + "IHHiIII", gh)[6]
