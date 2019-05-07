from analysis.packet import get_src_dst, get_base_pkt
from config import CLASSES
from utils.gen import pick_first_n


def get_label(mpath):

    idx = 0
    res = None

    for c in CLASSES:
        if c in mpath:
            res = idx
        idx += 1

    if res is None:
        raise Exception("Unknown label {}".format(mpath))

    return res


def explode_pcap_to_packets(path_pcap_label, num_packets):

    path = path_pcap_label[0]
    pcap = path_pcap_label[1]
    label = path_pcap_label[2]
    basedir = get_src_dst(get_base_pkt(pcap))

    return [
        (path, pkt, {
            "label": label,
            "index": idx,
            "basedir": basedir
        })
        for idx, pkt in pick_first_n(enumerate(pcap), num_packets)
    ]


