package main

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"
)

var p = Packet{
	Length: 56,
	Payload: Payload{
		Src:     2,
		Dst:     16383,
		Serial:  4,
		DevType: 2,
		Cmd:     2,
		CmdBody: CmdBody{
			Dev: Dev{
				DevName: String{
					Len: 8,
					S:   []byte("SENSOR01"),
				},
				DevProps: DevProps{
					EnvSensorDevProps: EnvSensorDevProps{
						Sensor: 15,
						Triggers: Array[Trigger]{
							Len: 4,
							Arr: []Trigger{
								{
									Op:    12,
									Value: 100,
									Name: String{
										Len: 6,
										S:   []byte("OTHER1"),
									},
								},
								{
									Op:    15,
									Value: 1200,
									Name: String{
										Len: 6,
										S:   []byte("OTHER2"),
									},
								},
								{
									Op:    0,
									Value: 100012,
									Name: String{
										Len: 6,
										S:   []byte("OTHER3"),
									},
								},
								{
									Op:    8,
									Value: 0,
									Name: String{
										Len: 6,
										S:   []byte("OTHER4"),
									},
								},
							},
						},
					},
				},
			},
		},
	},
}

func init() {
	CalculateTable()
	b, _ := p.marshal()
	p.Crc8 = ComputeCRC8(b[1:])
}

func TestEncode(t *testing.T) {
	var s string
	s = "OAL_fwQCAghTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI09w"

	ss, _ := p.Encode()
	if s != ss {
		t.Errorf("Expexted: %v\nGot: %v\n", s, ss)
	}

	pe, _ := Packet{}.Decode(ss)
	if !reflect.DeepEqual(pe, p) {
		t.Errorf("Expected %v\nGot %v", p, pe)
	}
}

func TestEncodeLight(t *testing.T) {
	pack := Packet{
		Length: 12,
		Payload: Payload{
			Src:     1,
			Dst:     16383,
			Serial:  1,
			DevType: 1,
			Cmd:     1,
			CmdBody: CmdBody{
				Dev: Dev{DevName: String{
					Len: 5,
					S:   []byte("HUB01"),
				}},
			},
		},
	}
	b, _ := pack.marshal()
	pack.Crc8 = ComputeCRC8(b[1:])
	s := "DAH_fwEBAQVIVUIwMeE"
	ss, _ := pack.Encode()

	if s != ss {
		t.Errorf("Expected: %v\nGot: %v", s, ss)
	}

	var pp Packet
	pp, _ = pp.Decode(s)

	if !reflect.DeepEqual(pack, pp) {
		t.Errorf("Expected %v\nGot %v", pack, pp)
	}
}

func FuzzUint(f *testing.F) {
	f.Add(uint(2345234))
	f.Fuzz(func(t *testing.T, u1 uint) {
		u := Uint(u1)
		uu, _ := Uint(0).Unmarshal(u.Marshal())
		if u != uu {
			t.Errorf("Expected %v, got %v", u, uu)
		}
	})
}

func TestULEB128(t *testing.T) {
	b := []byte{136, 183, 1, 4, 7}
	u, i := Uint(0).Unmarshal(b)
	fmt.Println(u, i)
	if u != Uint(23432) {
		t.Fail()
	}
}

func TestTrigger(t *testing.T) {
	tr := Trigger{
		Op:    40,
		Value: 1234509,
		Name: String{
			Len: 9,
			S:   []byte("Abreandra"),
		},
	}
	tt, _ := Trigger{}.Unmarshal(tr.Marshal())

	if !reflect.DeepEqual(tr, tt) {
		t.Fail()
	}
}

func TestMulti(t *testing.T) {
	codes := []string{
		"DAH_fwEBAQVIVUIwMeE",
		"DAH_fwIBAgVIVUIwMak",
		"OAL_fwMCAQhTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI03Q",
		"OAL_fwQCAghTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI09w",
		"BQECBQIDew",
		"EQIBBgIEBKUB4AfUjgaMjfILrw",
		"IgP_fwcDAQhTV0lUQ0gwMQMFREVWMDEFREVWMDIFREVWMDO1",
		"IgP_fwgDAghTV0lUQ0gwMQMFREVWMDEFREVWMDIFREVWMDMo",
		"BQEDCQMDoA",
		"BgMBCgMEAac",
		"DQT_fwsEAQZMQU1QMDG8",
		"DQT_fwwEAgZMQU1QMDGU",
		"BQEEDQQDqw",
		"BgQBDgQEAaw",
		"BgEEDwQFAeE",
		"DwX_fxAFAQhTT0NLRVQwMQ4",
		"DwX_fxEFAghTT0NLRVQwMc0",
		"BQEFEgUD5A",
		"BgUBEwUEAQ8",
		"BgUBEwUEAQ8",
		"Dgb_fxUGAgdDTE9DSzAxsw",
		"DAb_fxgGBpabldu2NNM",
	}

	for i, code := range codes {
		i := i
		code := code
		t.Run(fmt.Sprint("Test ", i), func(t *testing.T) {
			temp, _ := Packet{}.Decode(code)
			got, _ := temp.Encode()
			if got != code {
				t.Errorf("\nExpected %s\nGot %s", code, got)
			}
		})
	}
}

func TestWait(t *testing.T) {
	fmt.Println(base64.RawURLEncoding.DecodeString("EQIBBgIEBKUB4AfUjgaMjfILrw"))
	fmt.Println(Packet{}.Decode("EQIBBgIEBKUB4AfUjgaMjfILrw"))
}
