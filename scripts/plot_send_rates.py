#!/usr/bin/env python3

import glob
import json
import math
import numpy as np
# import matplotlib.pyplot as plt
import plotly.graph_objects as go
import sys

order = ["0us", "1us", "5us", "10us", "25us", "50us", "100us", "500us", "1ms", "2.5ms", "5ms", "10ms"]

def main():

	data = {}

	root = None if len(sys.argv) == 1 else sys.argv[1]
	for path in glob.glob("**/*.stats.out", root_dir=root):
		s = path.split("/")
		t = s[0]
		if t not in data:
			data[t] = {}
		data[t] = []
		with open(root+path, "r") as f:
			for line in f.readlines():
				if "stats " in line:
					pps = line.split(" ")[-2]
					data[t].append(float(pps))

	fig = go.Figure()
	# for tag, v in data.items():
	for tag in order:
		v = data[tag]
		fig.add_trace(go.Scatter(
			name = tag,
			x = list([(x*5 + 2.5)/3600 for x in range(len(v))]),
			y = v
		))

	fig.update_xaxes(title_text='Time (h)')
	fig.update_yaxes(title_text='Probes (pps)')
	fig.update_yaxes(type="log")
	fig.show()

if __name__ == "__main__":
	main()
