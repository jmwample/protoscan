#!/usr/bin/env python3

import glob
import json
import math
import numpy as np
# import matplotlib.pyplot as plt
import plotly.graph_objects as go

def main():

	data = {}

	for path in glob.glob("out-*/**/*.out"):
		s = path.split("/")
		w = int(s[1])
		t = s[2]
		if t not in  data:
			data[t] = {}
		data[t][w] = {}
		with open(path, "r") as f:
			ppsa = []
			for line in f.readlines():
				if "stats " in line:
					pps = line.split(" ")[-2]

					ppsa.append(float(pps))
					data[t][w]["avg"] = np.mean(ppsa)
					data[t][w]["std"] = np.std(ppsa)


	fig = go.Figure()
	for tag, v in data.items():
		data[tag] = {k:v[k] for k in sorted(v.keys())}
		fig.add_trace(go.Scatter(
			name = tag,
			x = list(data[tag].keys()),
			y = [y["avg"] for y in data[tag].values()],
			error_y = dict(
				type='data',
				visible=True,
				array=[y["std"] for y in data[tag].values()]
			)
		))
		# plt.plot(data[tag].keys(), data[tag].values(), label = tag)

	fig.update_xaxes(title_text='Number of Workers')
	fig.update_yaxes(title_text='Probes (pps)')
	fig.update_xaxes(type="log")
	fig.show()

if __name__ == "__main__":
	main()