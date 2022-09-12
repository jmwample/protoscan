
class ipv6:
  SYNACK = """"""
  RST = """"""
  RSTACK = """"""
  HTTP = """"""
  ACK = """"""

class ipv4:
  HTTP = """"""
  SYNACK = """"""
  RST = """"""
  RSTACK = """"""
  ACK = """"""

class all:
  HTTP = """"""
  SYNACK = """"""
  RST = """"""
  RSTACK = """"""
  ACK = """"""


colors = {"HTTP": "#3FB389", "SYNACK":"#2C7196", "RST":"lightsalmon", "RSTACK":"indianred"}
data4 = {"HTTP": ipv4.HTTP, "SYNACK":ipv4.SYNACK, "RST":ipv4.RST, "RSTACK":ipv4.RSTACK}
data6 = {"SYNACK":ipv6.SYNACK, "RST":ipv6.RST, "RSTACK":ipv6.RSTACK}
