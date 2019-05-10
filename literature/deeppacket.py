import sys

from filepath.filepath import fp

from main import load_pcap
from utils.general import read_inputs, get_pcaps
from utils.sprk import get_spark_session

from pyspark.sql import Row

from analysis.flow import explode_pcap_to_packets

from scapy.all import *
from scapy.all import DNS, TCP, IPv6, IP, UDP

from utils.general import get_label


def filter_out_dns(pkt):
    return DNS not in pkt


def filter_out_empty_tcp(pkt):
    if TCP not in pkt:
        return True
    return len(pkt.getlayer(TCP).payload) > 0


def filter_out_non_ip(pkt):
    return IP in pkt or IPv6 in pkt


def filter_out_irrelavent(arg):
    _, _, pkt = arg
    return all([f(pkt) for f in (
        filter_out_dns,
        filter_out_empty_tcp,
        filter_out_non_ip,
    )])


def remove_ethernet_header(arg):
    f, i, pkt = arg
    return f, i, pkt.payload


def _to_bytes(pkt):
    return bytearray(str(pkt))


def _get_ip_layer(pkt):
    return pkt.getlayer(IP) if IP in pkt \
        else pkt.getlayer(IPv6)


def _get_header_length(pkt):
    return len(pkt) - len(pkt.payload)


def _get_zero_address(pkt):
    return '0.0.0.0' if IP in pkt \
        else '::1'


def _get_ip_header(pkt):

    # extract IP layer
    netlayer = _get_ip_layer(pkt).copy()
    zero = _get_zero_address(pkt)

    # mask IP addresses
    netlayer.src = zero
    netlayer.dst = zero

    # return header bytes
    mbytes = _to_bytes(netlayer)
    return mbytes[:_get_header_length(pkt)]


def convert_to_bytes(arg):
    f, i, pkt = arg

    # get layer-3
    netlayer = _get_ip_layer(pkt)

    # get IP payload bytes
    mbytes = bytearray(str(netlayer.payload))

    # zero pad UDP header
    if UDP in pkt:
        mbytes = mbytes[:8] + b'\0' * 12 + mbytes[8:]

    # concat IP header
    mbytes = _get_ip_header(pkt) + mbytes

    # zero pad
    mbytes = list(mbytes) + max(len(mbytes) - 1500, 0) * [0]

    # use first 1500 byts
    mbytes = mbytes[:1500]

    assert len(mbytes) == 1500

    return f, i, mbytes


def to_rows(arg):

    fpath, idx, mbytes = arg
    assert isinstance(mbytes, bytearray)
    label = get_label(fpath)

    mdict = {
        "label": label
    }

    for i in range(1500):
        mdict["b%03d" % i] = mbytes[i]

    return Row(**mdict)


def deep_packet():

    # get input and output dir
    data_dir, out_file = read_inputs()

    # list PCAP files
    pcap_list = get_pcaps(data_dir)

    spark, sc, sqlContext = get_spark_session()

    # make RDD
    paths_rdd = sc.parallelize(pcap_list)

    analyzed_rdd = paths_rdd \
        .repartition(512) \
        .map(load_pcap) \
        .flatMap(explode_pcap_to_packets) \
        .filter(filter_out_irrelavent) \
        .map(remove_ethernet_header) \
        .map(convert_to_bytes) \
        .map(to_rows)

    df = analyzed_rdd.toDF()

    df.repartition(512).coalesce(1).write.csv(out_file, header=True)


def analysis():

    global psizes, res

    # get input and output dir
    data_dir, out_dir = read_inputs()

    # list PCAP files
    pcap_list = get_pcaps(data_dir)

    spark, sc, sqlContext = get_spark_session()

    # make RDD
    paths_rdd = sc.parallelize(pcap_list)

    psizes = paths_rdd \
        .repartition(512) \
        .map(load_pcap) \
        .flatMap(explode_pcap_to_packets) \
        .filter(filter_out_irrelavent) \
        .map(lambda s: len(s[2].payload))

    res = psizes.collect()

    psizes.persist()\
        .map(lambda s: Row(size=s))\
        .toDF()\
        .createOrReplaceTempView("psizes")

    spark.sql("""
        select size, count(size) as cnt
        from psizes
        group by size
        order by size
    """).repartition(512)\
        .coalesce(1)\
        .write\
        .csv(out_dir + "/hist-512.csv", header=True)


def __main__():
    deep_packet()


if __name__ == "__main__":
    __main__()


