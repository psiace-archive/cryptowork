from typing import ByteString, List


def string_to_bitlist(data: ByteString) -> List[int]:
    """Turn the string data, into a list of bits (1, 0)'s"""
    l = len(data) * 8
    result = [0] * l
    pos = 0
    for ch in data:
        i = 7
        while i >= 0:
            if ch & (1 << i) != 0:
                result[pos] = 1
            else:
                result[pos] = 0
            pos += 1
            i -= 1

    return result


def bitlist_to_string(data: List[int]) -> ByteString:
    """Turn the list of bits -> data, into a string"""
    result = []
    pos = 0
    c = 0
    while pos < len(data):
        c += data[pos] << (7 - (pos % 8))
        if (pos % 8) == 7:
            result.append(c)
            c = 0
        pos += 1

    return bytes(result)
