

def pick_first_n(gen, n):
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



