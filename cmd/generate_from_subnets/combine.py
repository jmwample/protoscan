#!/usr/bin/env python3

import sys

def main():
    fp1 = sys.argv[1]
    fp2 = sys.argv[2]

    addrs1 = []

    addrs2 = []


    with open(fp1, "r") as f1:
        for line in f1.readlines():
            addrs1.append(line.strip())

    with open(fp2, "r") as f2:
        for line in f2.readlines():
            addrs2.append(line.strip())


    if len(addrs1) != len(addrs2):
        print("why len not match")
        sys.exit(1)

    for i in range(len(addrs1)):
        print("{} {}".format(addrs1[i], addrs2[i]))

if __name__ == "__main__":
    main()