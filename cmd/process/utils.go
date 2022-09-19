package main

import (
	"encoding/json"
	"io/ioutil"
)

// KeyTable stores domain to port mappings
type KeyTable struct {

	// forward
	F map[string]uint16
	// reverse
	R map[uint16]string
}

func parseDKT(path string) (*KeyTable, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dkt KeyTable
	err = json.Unmarshal(content, &dkt)
	return &dkt, nil
}

type u8f func(*PacketDetails) uint8
type u16f func(*PacketDetails) uint16

func uniqueCountsU8(arr []uint8) map[uint8]int {
	//Create a   dictionary of values for each element
	dict := make(map[uint8]int)
	for _, num := range arr {
		dict[num] = dict[num] + 1
	}
	return dict
}

func uniqueCountsU16(arr []uint8) map[uint8]int {
	//Create a   dictionary of values for each element
	dict := make(map[uint8]int)
	for _, num := range arr {
		dict[num] = dict[num] + 1
	}
	return dict
}

func u8fTTL(p *PacketDetails) uint8 {
	return p.IpTTL
}

func u8fFlags(p *PacketDetails) uint8 {
	return p.TcpFlags
}

func u8fIPIDUpper(p *PacketDetails) uint8 {
	return uint8(p.IpID >> 8)
}

func u8fIPIDLower(p *PacketDetails) uint8 {
	return uint8(p.IpID >> 8)
}
