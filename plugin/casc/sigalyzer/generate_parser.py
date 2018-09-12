from __future__ import absolute_import

from .clamav import parse_signature

def main():
    parse_signature("Win.Agent.Generic:1:5,7:4f5c*2345{-12}ccdd((aa|f?)|bb|cc)????00")

if __name__ == "__main__":
    main()
