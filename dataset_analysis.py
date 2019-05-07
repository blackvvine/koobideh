
import sys

from filepath.filepath import fp


def print_help():
    pass


if len(sys.argv) < 2:
    print_help()
    exit(1)


df_path = fp(sys.argv[1])



