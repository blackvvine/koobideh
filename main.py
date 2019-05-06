
import shutil

from filepath.filepath import fp

from scapy.all import *
from scapy.utils import rdpcap
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from parse import get_base_pkt, get_src_dst, check_tls
from utils import get_logger
from utils.gen import pick_first_n

from pyspark import SparkConf, SparkContext
from pyspark.sql import SparkSession, SQLContext, Row

from config import CLASSES, FEATURE_SIZE

logger = get_logger("Pre-process")


def print_help():
    pass


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


def explode_pcap_to_packets(path_pcap_label):

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
        for idx, pkt in pick_first_n(enumerate(pcap), FEATURE_SIZE)
    ]


def _add_dict(d1, d2):
    d = dict(d1)
    d.update(d2)
    return d


def apply_function_to_pkt(function):
    """
    returns a function
    :param function:
    :return:
    """
    return lambda pkt_tuple: (
        pkt_tuple[0],
        pkt_tuple[1],
        _add_dict(pkt_tuple[2], function(pkt_tuple[1]))
    )


def _fix_length(iterable, value='0'):
    """
    Picks the first N of the iterable, returns
    an array and pads the end of it with given
    value if necessary
    :param iterable:
    :param value:
    :return:
    """
    arr = list(pick_first_n(iterable, FEATURE_SIZE))
    return arr + [value] * max(0, FEATURE_SIZE - len(arr))


def _get_direction_seq(cap):

    base_src_dst = get_src_dst(get_base_pkt(cap))

    return (1 if get_src_dst(pkt) == base_src_dst else -1
            for pkt in cap)


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
        "packet_size": (str(i) for i in _fix_length(packet_size_seq)),
        "direction": (str(i) for i in _fix_length(direction_seq)),
        "tls": int(has_tls),
        "https": int(has_https),
        "http2": int(has_http2),
        "label": label
    }


def _get_size_seq(pcap):

    return (len(pkt.getlayer(IP)) if IP in pkt else len(pkt.getlayer(IPv6)) for pkt in pcap)


def analysis_to_row(analysis):

    d = {}
    d.update({"p_%03d" % (i+1,): v for i, v in enumerate(analysis["packet_size"])})
    d.update({"d_%03d" % (i+1,): v for i, v in enumerate(analysis["direction"])})
    d.update({
        "http2": analysis["http2"],
        "https": analysis["https"],
        "tls": analysis["tls"],
        "label": analysis["label"]
    })

    for k, v in d.items():
        if v is None:
            raise Exception("Field %s is null" % k)
        try:
            int(v)
        except Exception as e:
            raise Exception("Non-integer value {} for {}".format(v, k))

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
pcaps_rdd = paths_rdd.repartition(512).map(load_pcap)

analyzed_rdd = pcaps_rdd.map(analyze_pcap).map(analysis_to_row)

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


