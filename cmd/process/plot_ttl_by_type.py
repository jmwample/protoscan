#!/usr/bin/env python3

import plotly.graph_objects as go
from plotly.subplots import make_subplots
import sys

# appending a path
sys.path.append('ttls_cn_aug4')
  
# importing required module
import tls
from tls import colors, data4, data6

def main():
  counts = {}
  ttls = {}


  fig = make_subplots(rows=2, cols=1,subplot_titles=("IPv4", "IPv6"))

  for k, v in data4.items():
    c, t = parse(v)
    counts[k] = c
    ttls[k] = t

  for key, count in counts.items():
    fig.append_trace(go.Bar(x=ttls[key], y=count, name = key, legendgroup=key, marker_color=colors[key]), row=1, col=1)

  counts = {}
  ttls = {}

  for k, v in data6.items():

    c, t = parse(v)
    counts[k] = c
    ttls[k] = t

  for key, count in counts.items():
    fig.append_trace(go.Bar(x=ttls[key], y=count, name = key, legendgroup=key, showlegend=False,  marker_color=colors[key]), row=2, col=1)

  fig.update_yaxes(type="log", title_text="Count (log)")
  fig.update_xaxes(title_text="TTL", range=[0,256])
  # fig.update_layout(barmode="stack")
  fig.update_layout(legend=dict(groupclick="toggleitem"))
  fig.update_layout(legend=dict(y=0.5))
  fig.show()

def parse(s):
	counts = []
	ttls = []
	for line in s.split("\n"):
		parts = line.strip().split(" ")
		counts.append(int(parts[0]))
		ttls.append(int(parts[1]))

	return counts, ttls



if __name__ == "__main__":
  main()
