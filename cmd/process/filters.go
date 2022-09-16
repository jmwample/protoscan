package main

type packetFilter func(*PacketDetails) *PacketDetails

// composeFilters
func cf(fs []packetFilter) packetFilter {

	defaultF := func(pd *PacketDetails) *PacketDetails {
		return pd
	}

	if len(fs) == 0 {
		return defaultF
	}

	return func(pd *PacketDetails) *PacketDetails {
		for _, f := range fs {
			pd = f(pd)
		}
		return pd
	}
}

func selectSYNACK(p *PacketDetails) *PacketDetails {
	if p == nil || p.TcpFlags != 0x12 {
		return nil
	}
	return p
}

func selectRST(p *PacketDetails) *PacketDetails {
	if p == nil || p.TcpFlags != 0x04 {
		return nil
	}
	return p
}

func selectRSTACK(p *PacketDetails) *PacketDetails {
	if p == nil || p.TcpFlags != 0x14 {
		return nil
	}
	return p
}

func selectHTTP(p *PacketDetails) *PacketDetails {
	if p == nil || !p.ContainsHTTP {
		return nil
	}
	return p
}

func selectIPv6(p *PacketDetails) *PacketDetails {
	if p == nil || !p.IPv6 {
		return nil
	}
	return p
}

func selectIPv4(p *PacketDetails) *PacketDetails {
	if p == nil || !p.IPv4 {
		return nil
	}
	return p
}

func newSelectIPID(id uint16) packetFilter {
	return func(p *PacketDetails) *PacketDetails {
		if p == nil || p.IpID != id {
			return nil
		}
		return p
	}
}
