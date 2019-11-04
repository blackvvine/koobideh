
import sys

from filepath.filepath import fp

from kabab.utils import get_logger
from kabab.utils.sprk import read_csv, get_spark_session


logger = get_logger("Analysis")


def print_help():
    pass


def tls_stats(spark, df):

    df.createOrReplaceTempView("dataset")

    return spark.sql("select tls, https, http2, count(*) from dataset group by tls, https, http2").collect()


def __main__():

    if len(sys.argv) < 2:
        print_help()
        exit(1)

    df_path = fp(sys.argv[1])

    # load spark session
    spark, sc, sqlContext = get_spark_session()

    # load dataset file
    df = read_csv(spark, df_path.path())

    stats = tls_stats(spark, df)

    logger.info("TLS stats: %s", stats)


if __name__ == "__main__":
    __main__()


