from packet_process import check_packet_tls
from utils import get_logger


# logger is parse
logger = get_logger("Parse")


def get_base_pkt(cap):
    return cap[0]


def check_tls(pcap):

    has_tls, has_h1, has_h2 = False, False, False

    for pkt in pcap:

        a = check_packet_tls(pkt)

        has_tls = has_tls or a["has_tls"]
        has_h1 = has_h1 or a["has_h1"]
        has_h2 = has_h2 or a["has_h2"]

    return has_tls, has_h1, has_h2


