import sys

from filepath.filepath import fp

from main import load_pcap
from utils.general import read_inputs, get_pcaps
from utils.sprk import get_spark_session

from analysis.flow import explode_pcap_to_packets


def __main__():

    # get input and output dir
    data_dir, out_file = read_inputs()

    # list PCAP files
    pcap_list = get_pcaps(data_dir)

    spark, sc, sqlContext = get_spark_session()

    # make RDD
    paths_rdd = sc.parallelize(pcap_list)

    analyzed = paths_rdd \
        .repartition(512) \
        .map(load_pcap) \
        .flatMap(explode_pcap_to_packets) \
        .map(lambda s: len(s))


if __name__ == "__main__":
    __main__()


