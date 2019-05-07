import shutil

from filepath.filepath import fp
from scapy.all import *

from flow_process import get_base_pkt, check_tls
from packet_process import get_src_dst
from parse_tools import get_label
from utils import get_logger
from utils.gen import pick_first_n, force_length

from pyspark.sql import Row

from config import FEATURE_SIZE
from utils.sprk import get_spark_session, read_csv, write_csv

logger = get_logger("Pre-process")


def print_help():
    pass


def load_pcap(pf):
    """
    Read pcap file into Scapy Ether objects
    :return: File path - Ether object tuples
    """
    fpath = pf.path()
    return fpath, rdpcap(fpath)


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


def _get_direction_seq(pcap):

    base_src_dst = get_src_dst(get_base_pkt(pcap))

    dir_seq = (1 if get_src_dst(pkt) == base_src_dst else -1 for pkt in pcap)

    return {
        "direction": force_length(dir_seq, FEATURE_SIZE)
    }


def _get_tls_info(pcap):
    has_tls, has_https, has_http2 = check_tls(pcap)
    return {
        "tls": int(has_tls),
        "https": int(has_https),
        "http2": int(has_http2)
    }


def _get_size_seq(pcap):

    size_seq = (len(pkt.payload) for pkt in pcap)

    return {
        "packet_size": force_length(size_seq, FEATURE_SIZE)
    }


def branch_per_flow_feature(flow_args):
    fpath, pcap = flow_args
    return [
        (fpath, (pcap, lambda pcap: _get_size_seq(pcap))),
        (fpath, (pcap, lambda pcap: _get_direction_seq(pcap))),
        (fpath, (pcap, lambda pcap: _get_tls_info(pcap))),
        (fpath, (pcap, lambda _: {"label": get_label(fpath)})),
    ]


def execute_pcap_command(arg):
    # TODO check whether omitting PCAP in arg and loading PCAP file here would be faster
    fpath, (pcap, pcap_func) = arg
    return fpath, pcap_func(pcap)


def merge_dicts(d1, d2):
    res = dict()
    res.update(d1)
    res.update(d2)
    return res


def analysis_to_row(arg):

    fpath, analysis = arg

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


def __main__():

    # parse input
    if len(sys.argv) < 2:
        print_help()
        exit(1)

    # parse args
    arg_dict = dict(list(enumerate(sys.argv)))
    data_dir = fp(sys.argv[1])  # ARG 1 (required) input dir
    out_file = arg_dict.get(2, "output.csv")  # ARG 2 (optional) output file (default: output.csv)
    tmp_file = out_file + ".tmp"

    # list PCAP files
    pcap_list = list([p for p in data_dir.find_files() if p.ext() not in ['json', 'csv', 'txt', 'data']])

    spark, sc, sqlContext = get_spark_session()

    # make RDD
    paths_rdd = sc.parallelize(pcap_list)

    # load PCAP
    analyzed_rdd = paths_rdd \
        .repartition(512) \
        .map(load_pcap) \
        .flatMap(branch_per_flow_feature) \
        .map(execute_pcap_command) \
        .reduceByKey(merge_dicts) \
        .map(analysis_to_row)

    df = sqlContext.createDataFrame(analyzed_rdd)
    df.write.csv(tmp_file, header=True)

    load_again = read_csv(spark, tmp_file).coalesce(1)
    write_csv(load_again, out_file)

    shutil.rmtree(tmp_file)


if __name__ == "__main__":
    __main__()


