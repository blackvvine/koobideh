from kabab.flow import check_tls, size_seq, dir_seq, inter_arrival
from kabab.utils.general import get_label, read_inputs, get_pcaps, load_pcap
from kabab.utils import get_logger
from kabab.utils.gen import force_length

from pyspark.sql import Row

from kabab.config import FEATURE_SIZE
from kabab.utils.sprk import get_spark_session, read_csv, write_csv

import shutil

logger = get_logger("Pre-process")


def _get_direction_seq(pcap):

    return {
        "direction": force_length(dir_seq(pcap), FEATURE_SIZE, pad=0)
    }


def _get_tls_info(pcap):

    has_tls, has_https, has_http2 = check_tls(pcap)

    return {
        "tls": int(has_tls),
        "https": int(has_https),
        "http2": int(has_http2)
    }


def _get_size_seq(pcap):
    return {
        "packet_size": force_length(size_seq(pcap), FEATURE_SIZE, pad=0)
    }


def _get_time_seq(pcap):
    return {
        "inter_arrival": force_length(inter_arrival(pcap), FEATURE_SIZE, pad=0.0)
    }


def _get_pcap_size(pcap):
    return {
        "num_packets": len(pcap),
        "num_bytes": sum([len(i) for i in pcap])
    }


def branch_per_flow_feature(flow_args):
    fpath, pcap = flow_args
    return [
        (fpath, (pcap, lambda pcap: _get_size_seq(pcap))),
        (fpath, (pcap, lambda pcap: _get_direction_seq(pcap))),
        (fpath, (pcap, lambda pcap: _get_tls_info(pcap))),
        (fpath, (pcap, lambda pcap: _get_time_seq(pcap))),
        (fpath, (pcap, lambda pcap: _get_pcap_size(pcap))),
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

    l2d = lambda l, prefix: {"%s_%05d" % (prefix, i + 1): v for i, v in enumerate(l)}

    d = {}
    d.update(l2d(analysis["packet_size"], "p"))
    d.update(l2d(analysis["direction"], "d"))
    d.update(l2d(analysis["inter_arrival"], "t"))
    d.update({
        "http2": analysis["http2"],
        "https": analysis["https"],
        "tls": analysis["tls"],
        "label": analysis["label"],
        "num_packets": analysis["num_packets"],
        "num_bytes": analysis["num_bytes"],
    })

    for k, v in d.items():
        if v is None or v is "":
            raise Exception("Field %s is null" % k)
        try:
            int(v)
        except Exception as e:
            raise Exception("Non-integer value {} for {}".format(v, k))

    return Row(**d)


def filter_tiny_flows(arg):
    _, pcap = arg
    return len(pcap) >= 10


def get_flows_df(spark, sc, sqlContext, data_dir):

    # list PCAP files
    pcap_list = get_pcaps(data_dir)

    # make RDD
    paths_rdd = sc.parallelize(pcap_list)

    # load PCAP
    analyzed_rdd = paths_rdd \
        .repartition(512) \
        .map(load_pcap) \
        .filter(filter_tiny_flows) \
        .flatMap(branch_per_flow_feature) \
        .map(execute_pcap_command) \
        .reduceByKey(merge_dicts) \
        .map(analysis_to_row)

    df = sqlContext.createDataFrame(analyzed_rdd)
    return df


def _analysis():

    data_dir, out_file = read_inputs()
    spark, sc, sqlContext = get_spark_session()

    df = get_flows_df(spark, sc, sqlContext, data_dir)
    df.createOrReplaceTempView("flows")

    # number of entries in dataset per class
    # noinspection SqlDialectInspection,SqlNoDataSourceInspection
    spark.sql("""
        select * from (
            select label as class_id, 
                  count(*) as num_flows, 
                  sum(num_bytes) as total_bytes, 
                  sum(num_packets) as total_packets 
                  from flows group by label
            ) as m 
            inner join names on label_id=m.class_id 
            order by m.class_id
    """)\
        .coalesce(1)\
        .write\
        .csv("%s-1.csv" % out_file, header=True)

    # TLS (http2/s) stats in dataset
    # noinspection SqlDialectInspection,SqlNoDataSourceInspection
    spark.sql("""
    select http2, https, tls, count(*) as num_flows, sum(num_packets) as num_packets, sum(num_bytes) as total_bytes 
    from flows group by http2, https, tls
    """)\
        .coalesce(1)\
        .write\
        .csv("%s-2.csv" % out_file, header=True)


def __main__():

    data_dir, out_file = read_inputs()
    tmp_file = out_file + ".tmp"

    spark, sc, sqlContext = get_spark_session()

    df = get_flows_df(spark, sc, sqlContext, data_dir)
    df.write.csv(tmp_file, header=True)

    load_again = read_csv(spark, tmp_file).coalesce(1)
    write_csv(load_again, out_file)

    shutil.rmtree(tmp_file)


if __name__ == "__main__":
    __main__()


