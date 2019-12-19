from pyspark import SparkConf, SparkContext
from pyspark.sql import SparkSession, SQLContext


def get_spark_session(cores=64):
    # load Spark session
    spark = SparkSession.builder.master("local[%d]" % cores).appName("PySparkShell").getOrCreate()
    conf = SparkConf().setAppName("PySparkShell").setMaster("local[%d]" % cores)
    sc = SparkContext.getOrCreate(conf)
    sqlContext = SQLContext(sc)
    return spark, sc, sqlContext


def read_csv(spark, infile):
    return spark.read \
        .option("header", "true") \
        .option("inferSchema", "true") \
        .csv(infile)


def write_csv(df, outfile):
    df.write.csv(outfile, header=True)


