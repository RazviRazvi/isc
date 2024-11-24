#!/usr/bin/python3
import math
import base64
import random


def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


class LCG:
    def __init__(self, a, b):
        self.a = a
        self.b = b
        self.mod = 2 ** 16
        self.state = 0

    def next(self):
        self.state = (self.a * self.state + self.b) % self.mod
        return self.state


if __name__ == '__main__':
    flag = "This_Is_NOT_SpeishFlag{asdfg_not_that_easy}"
    plaintext = "Stay your hand! Gotcha!\n" + \
        "You do not know this part, \n" + \
        "but it ends with a\n" + flag
    # note: message is always ASCII!
    bintext = plaintext.encode("ASCII")

    params = [random.randint(1337, 10000) for _ in (1, 2)]
    lcg = LCG(*params)
    states = [lcg.next() for _ in range(math.ceil(len(bintext) / 2))]
    key = b"".join([state.to_bytes(2, "little") for state in states])

    ciphertext = xor(bintext, key)
    print(base64.b64encode(ciphertext).decode("ASCII"))

