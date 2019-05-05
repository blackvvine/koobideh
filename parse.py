
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy_ssl_tls.ssl_tls import TLSServerHello, TLSClientHello, TLS, TLSALPNProtocol
from utils import get_logger


# logger is parse
logger = get_logger("Parse")


def _get_addr():
    pass


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


def get_src_dst(pkt):

    if TCP in pkt or UDP in pkt:
        return _get_tcp_udp_src_dst(pkt)
    elif IP in pkt or IPv6 in pkt:
        return _get_ip_src_dst(pkt)
    else:
        return pkt.src, pkt.dst


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

    has_tls = False
    has_h1 = False
    has_h2 = False

    for pkt in pcap:
        if TLS in pkt:
            has_tls = True
        if TLSServerHello in pkt:
            for protocol in extract_next_protocol(pkt):
                if re.match(r"http/1.*", protocol):
                    has_h1 = True
                if "h2" in protocol:
                    has_h2 = True

    return has_tls, has_h1, has_h2






