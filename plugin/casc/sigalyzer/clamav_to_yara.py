from __future__ import absolute_import

import os
import sys
import argparse
import logging

from .clamav import parse_signature
from .yara import convert_to_yara

log = logging.getLogger("clamav_to_yara")

def main(args, env):
    for line in sys.stdin.readlines():
        try:
            clamav_signature = parse_signature(line.strip())
            if clamav_signature is None:
                log.warn("Cannot parse ClamAV signature '%s'", line.strip())
                continue
            yara_rule = convert_to_yara(clamav_signature)
            print(yara_rule)
        except:
            log.exception("")

        


def parse_args():
    parser = argparse.ArgumentParser(description = "Find common ngrams in binary files")
    parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity")

    args = parser.parse_args()

    try:
        loglevel = {
            0: logging.ERROR,
            1: logging.WARN,
            2: logging.INFO}[args.verbose]
    except KeyError:
        loglevel = logging.DEBUG
    logging.basicConfig(level = loglevel)
    logging.getLogger().setLevel(loglevel)

    return args

if __name__ == "__main__":
    ret = main(parse_args(), os.environ)
    if ret is not None:
        sys.exit(ret)
