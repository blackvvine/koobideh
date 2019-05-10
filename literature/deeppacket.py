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
from config import PARTITIONS


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
    return filter_out_dns(pkt) and \
        filter_out_empty_tcp(pkt) and \
        filter_out_non_ip(pkt)


def _get_ip_layer(pkt):
    return pkt.getlayer(IP) if IP in pkt \
        else pkt.getlayer(IPv6)


def _get_zero_address(pkt):
    return '0.0.0.0' if IP in pkt \
        else '::1'


def convert_to_bytes(arg):
    f, i, pkt = arg

    assert IP in pkt or IPv6 in pkt

    # get layer-3
    netlayer = _get_ip_layer(pkt).copy()

    # mask IP
    zero = _get_zero_address(pkt)
    netlayer.src = zero
    netlayer.dst = zero

    # add IP header
    header_length = len(netlayer) - len(netlayer.payload)
    mbytes = str(netlayer)[:header_length]

    # zero-pad UDP header
    if UDP in pkt:
        mbytes += str(netlayer.getlayer(UDP))[:8]
        mbytes += '\0' * 12
        mbytes += str(netlayer.getlayer(UDP))[8:]
    else:
        mbytes += str(netlayer.payload)

    # use first 1500 bytes
    mbytes = mbytes[:1500]

    # convert to integer values and zero-pad
    mbytes = [ord(c) for c in mbytes]
    mbytes += max(1500 - len(mbytes), 0) * [0]

    assert len(mbytes) == 1500

    return f, i, mbytes


def to_row(arg):

    fpath, idx, mbytes = arg
    assert len(mbytes) == 1500
    for c in mbytes:
        assert type(c) == int and 0 <= c <= 255

    mdict = {"label": (get_label(fpath))}

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
        .repartition(PARTITIONS) \
        .map(load_pcap) \
        .flatMap(explode_pcap_to_packets) \
        .filter(filter_out_irrelavent) \
        .map(convert_to_bytes) \
        .map(to_row)

    analyzed_rdd.toDF() \
        .repartition(PARTITIONS) \
        .coalesce(1) \
        .write \
        .csv(out_file, header=True)


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
        .repartition(PARTITIONS) \
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
        select 
            size, 
            count(size) as cnt
        from psizes
        group by size
        order by size
    """) \
        .coalesce(1)\
        .write\
        .csv(out_dir + "/hist-1.csv", header=True)


def __main__():
    deep_packet()


if __name__ == "__main__":
    __main__()


