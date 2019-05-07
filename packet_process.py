import re

from scapy_ssl_tls.ssl_tls import TLS, TLSServerHello

from flow_process import extract_next_protocol, _get_tcp_udp_src_dst, _get_ip_src_dst


def get_first_n_bytes(pcap, n=784):
    return pick_first_n((len(pkt.load) for pkt in pcap), n=n)


def check_packet_tls(pkt):

    has_tls, has_h1, has_h2 = False, False, False

    if TLS in pkt:
        has_tls = True

    if TLSServerHello in pkt:
        for protocol in extract_next_protocol(pkt):
            if re.match(r"http/1.*", protocol):
                has_h1 = True
            if "h2" in protocol:
                has_h2 = True

    return {
        "has_tls": has_tls,
        "has_h1": has_h1,
        "has_h2": has_h2
    }


def get_src_dst(pkt):

    if TCP in pkt or UDP in pkt:
        return _get_tcp_udp_src_dst(pkt)
    elif IP in pkt or IPv6 in pkt:
        return _get_ip_src_dst(pkt)
    else:
        return pkt.src, pkt.dst