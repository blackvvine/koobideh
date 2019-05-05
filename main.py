import os
import shutil
import sys
import pdb

from filepath.filepath import fp

from pyspark import SparkConf, SparkContext
from pyspark.sql import SQLContext, Row, SparkSession

from config import FEATURE_SIZE, CLASSES

import scapy
from scapy.all import *
from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP

from parse import get_base_pkt, get_src_dst, check_tls


def print_help():
    pass


def get_label(mpath):
    idx = 0
    res = None
    for c in CLASSES:
        if c in mpath:
            res = idx
        idx += 1
    return res


def _to_str(seq):
    return (str(i) for i in seq)


def load_pcap(pf):
    """
    Read pcap file into file
    :param pf:
    :return:
    """
    fpath = pf.path()
    return rdpcap(fpath), get_label(fpath)


def _pick_first_n(gen, n):
    """
    Picks the first N elements of a generator
    """
    idx = 0
    if n > 0:
        for c in gen:
            idx += 1
            yield c
            if idx == n:
                break


def _fix_length(iterable, value='0'):
    """
    Picks the first N of the iterable, returns
    an array and pads the end of it with given
    value if necessary
    :param iterable:
    :param value:
    :return:
    """
    arr = list(_pick_first_n(iterable, FEATURE_SIZE))
    return arr + [value] * max(0, FEATURE_SIZE - len(arr))


def _get_direction_seq(cap):

    base_src_dst = get_src_dst(get_base_pkt(cap))

    return [1 if get_src_dst(pkt) == base_src_dst else -1
            for pkt in cap]


def analyze_pcap(args):
    """
    :param args: 2-tuple of loaded PCAP and its label (string)
    :return:
    """

    # unpack args
    pcap, label = args

    # get packet size stream
    packet_size_seq = _get_size_seq(pcap)

    # get packet direction stream
    direction_seq = _get_direction_seq(pcap)

    # check for TLS records
    has_tls, has_https, has_http2 = check_tls(pcap)

    return {
        "packet_size": _fix_length((str(i) for i in packet_size_seq)),
        "direction": _fix_length((str(i) for i in direction_seq)),
        "tls": int(has_tls),
        "https": int(has_https),
        "http2": int(has_http2),
        "label": label
    }


def _get_size_seq(pcap):

    return (pkt.getlayer(IP) for pkt in pcap)


def analysis_to_row(analysis):
    d = {}
    d.update({"p_%03d" % (i+1,): v for i, v in enumerate(analysis["packet_size"])})
    d.update({"d_%03d" % (i+1,): v for i, v in enumerate(analysis["direction"])})
    d.update({
        "http2": analysis["http2"],
        "https": analysis["https"],
        "label": analysis["label"]
    })
    return Row(**d)


# parse input
if len(sys.argv) < 2:
    print_help()
    exit(1)

# parse args
arg_dict = dict(list(enumerate(sys.argv)))
data_dir = fp(sys.argv[1]) # ARG 1 (required) input dir
out_file = arg_dict.get(2, "output.csv") # ARG 2 (optional) output file (default: output.csv)

# list PCAP files
pcap_list = list([p for p in data_dir.find_files() if p.ext() not in ['json', 'csv', 'txt', 'data']])

# load Spark session
spark = SparkSession.builder.master("local[64]").appName("PySparkShell").getOrCreate()
conf = SparkConf().setAppName("PySparkShell").setMaster("local[64]")
sc = SparkContext.getOrCreate(conf)
sqlContext = SQLContext(sc)

# make RDD
paths_rdd = sc.parallelize(pcap_list)

# load PCAP
captures_rdd = paths_rdd.map(load_pcap)

# analyze
analyzed_rdd = captures_rdd.map(analyze_pcap).map(analysis_to_row)

df = sqlContext.createDataFrame(analyzed_rdd)

df.write.csv(out_file + ".tmp", header=True)

load_again = spark.read \
    .option("header", "true") \
    .option("inferSchema", "true") \
    .csv(out_file + ".tmp")

load_again.coalesce(1) \
    .write \
    .csv(out_file, header=True)

shutil.rmtree(out_file + ".tmp")


