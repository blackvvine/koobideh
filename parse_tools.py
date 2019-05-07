from config import CLASSES


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