import os
import shutil
import sys
import pdb

from filepath.filepath import fp
from pyshark import FileCapture
from pyspark import SparkConf, SparkContext
import pyshark as psh
from pyspark.sql import SQLContext, Row, SparkSession

from config import FEATURE_SIZE, CLASSES


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


def load_pcap(pf):
    f = FileCapture(pf.path())
    f.load_packets()
    return f, get_label(pf.path())


def pick(gen, count):
    idx = 0
    if count > 0:
        for c in gen:
            idx += 1
            yield c
            if idx == count:
                break


def _fix_length(iterable, value='0'):
    arr = list(pick(iterable, FEATURE_SIZE))
    return arr + [value] * max(0, FEATURE_SIZE - len(arr))


def _get_base_pkt(cap):
    for pkt in cap:
        if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'tcp'):
            return pkt
    return cap[0]


def _get_src_dst(pkt):
    """
    return the peers of a flow a
    :param cap: flow PCAP file parsed as FileCapture
    :return: tuple of two strings
    """

    if hasattr(pkt, "ip"):
        if hasattr(pkt, "tcp"):
            first = pkt.ip.dst_host + "#" + pkt.tcp.dstport
            second = pkt.ip.src_host + "#" + pkt.tcp.srcport
            if pkt.tcp.dstport == 443 or pkt.tcp.dstport == 80:
                return first, second
            else:
                return second, first
        elif hasattr(pkt, "udp"):
            return pkt.ip.dst_host + "#" + pkt.udp.dstport, pkt.ip.src_host + "#" + pkt.udp.srcport
        else:
            return pkt.ip.dst_host + "#0", pkt.ip.src_host + "#0"
    elif hasattr(pkt, "eth"):
        return pkt.eth.dst, pkt.eth.src
    else:
        return "N/A", "N/A"


def _get_direction(cap):
    if not isinstance(cap, psh.FileCapture):
        raise Exception("Illegal argument type: %s" % type(cap))

    basepkt = _get_base_pkt(cap)

    base_src_dst = _get_src_dst(basepkt)

    return ['1' if _get_src_dst(pkt) == base_src_dst
            else '-1'
            for pkt in cap]


def analyze_pcap(args):

    cap, label = args

    has_http2 = False
    has_https = False

    packet_size = _fix_length((str(pkt.captured_length) for pkt in cap))

    direction = _fix_length(_get_direction(cap))

    for p in cap:
        if hasattr(p, "ssl") and hasattr(p.ssl, "record"):
            if "http2" in p.ssl.record:
                has_http2 = True
                break
            elif "http-over-tls" in p.ssl.record:
                has_https = True
                break

    return {
        "packet_size": packet_size,
        "direction": direction,
        "http2": int(has_http2),
        "https": int(has_https),
        "label": label
    }


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

arg_dict = dict(list(enumerate(sys.argv)))
data_dir = fp(sys.argv[1])
out_file = arg_dict.get(2, "output.csv")

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

load_again = spark.read.option("header", "true").option("inferSchema", "true").csv(out_file + ".tmp")

load_again.coalesce(1).write.csv(out_file, header=True)

shutil.rmtree(out_file + ".tmp")


