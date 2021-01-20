# Finds all start indices of b0 in b1, where b0 and b1 are both of type 'bytes'
def find_all(b0, b1):
    indices = set()
    lens = len(b0), len(b1)
    if lens[1] < lens[0]:
        return indices
    i = 0
    while i < lens[1] - lens[0] + 1:
        i = b1.find(b0, i)
        if i == -1:
            break
        indices.add(i)
        i += 1
    return indices
