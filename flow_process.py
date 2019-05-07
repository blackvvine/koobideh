from scapy_ssl_tls.ssl_tls import TLSServerHello, TLSClientHello

from packet_process import check_packet_tls
from utils import get_logger


# logger is parse
logger = get_logger("Parse")


def get_base_pkt(cap):
    return cap[0]


def _get_ip_src_dst(pkt):
    # layer = IPv6 if IPv6 in pkt else IP
    return pkt.src, pkt.dst


def _get_tcp_udp_src_dst(pkt, delimiter=":"):
    """
    :param pkt: Scapy frame
    :param layer: TCP or UDP
    :return:
    """
    ip = _get_ip_src_dst(pkt)
    return ip[0] + delimiter + str(pkt.sport), ip[1] + delimiter + str(pkt.dport)


def extract_next_protocol(pkt):

    if TLSServerHello in pkt:
        layer = TLSServerHello
    elif TLSClientHello in pkt:
        layer = TLSClientHello
    else:
        raise Exception("No ALPN data available")

    protocols = []

    for extension in pkt.getlayer(layer).extensions:
        if extension.type == 16:
            for protocol in extension.protocol_name_list:
                protocols.append(protocol.data)

    return protocols


def check_tls(pcap):

    has_tls, has_h1, has_h2 = False, False, False

    for pkt in pcap:

        a = check_packet_tls(pkt)

        has_tls = has_tls or a["has_tls"]
        has_h1 = has_h1 or a["has_h1"]
        has_h2 = has_h2 or a["has_h2"]

    return has_tls, has_h1, has_h2

