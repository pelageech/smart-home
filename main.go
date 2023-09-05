package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
)

const (
	CmdWhoIsHere = 0x1
	CmdIAmHere   = 0x2
	CmdGetStatus = 0x3
	CmdStatus    = 0x4
	CmdSetStatus = 0x5
	CmdTick      = 0x6

	TypeSmartHub  = 0x1
	TypeEnvSensor = 0x2
	TypeSwitch    = 0x3
	TypeLamp      = 0x4
	TypeSocket    = 0x5
	TypeClock     = 0x6

	TemperatureSensor = 0x0
	HumiditySensor    = 0x1
	LightSensor       = 0x2
	PollutionSensor   = 0x3

	HasTemperatureSensor = 0x1
	HasHumiditySensor    = 0x2
	HasLightSensor       = 0x4
	HasPollutionSensor   = 0x8

	TurnOnDevice    = 0b0001
	CompareMoreThan = 0b0010
	SensorMask      = 0b1100

	ExitStatusHttpError = 99
	Broadcast           = 0x3FFF
	FisrtPacketNumber   = 1
	HubName             = "HUB01"
	MaxDifference       = Uint(300)
)

var (
	ErrBadCode      = fmt.Errorf("code is not 200 or 204")
	ErrHttp         = fmt.Errorf("http error")
	ErrIO           = fmt.Errorf("io error")
	ErrPacketFormat = fmt.Errorf("packet format is incorrect")
	ErrCRC8         = fmt.Errorf("crc8 wrong calculation")

	// initial variables
	crcTable []byte

	startTimestamp Uint
	currentTime    Uint

	network = Network{
		Clock: Clock{},
		Switches: SwitchMap{
			MapName:  map[Uint]string{},
			Switches: map[string]Switch{},
		},
		Sensors: EnvSensorMap{
			MapName: map[Uint]string{},
			Envs:    map[string]EnvSensor{},
		},
		Devices: DeviceMap{
			MapName: map[Uint]string{},
			Device:  map[string]AbstractDevice{},
		},
	}

	// Очередь из пакетов, получаемых из сети, которые обрабатываются, и если надо,
	// создаётся новый пакет, добавляемый в очередь на отправку
	packetQueue []Packet

	// Очередь на отправку пакетов, когда пакетов на обработку больше нет,
	// все пакеты отправляются на сервер друг за другом.
	packetsToSend = make([]Payload, 0)

	serial Uint = 1

	name    = []byte(HubName)
	address Uint
)

/*
	-----------------------------
	Marshal/Unmarshal packet part
	-----------------------------
*/

// #######################################################
// Interfaces

type Marshaller interface {
	Marshal() []byte
}

type Unmarshaller interface {
	Unmarshal([]byte) (any, int)
}

type arrayMarshaller interface {
	Marshaller
	Unmarshaller
	Size() int
}

// #######################################################
// Uint

type Uint uint

func (u Uint) Marshal() []byte {
	return uleb128(uint(u))
}

func (u Uint) Unmarshal(b []byte) (any, int) {
	var shift uint
	l := 0
	total := uint(0)
	for {
		r := b[l]
		l++
		total |= uint(r&0x7F) << shift
		if r&0x80 == 0 {
			break
		}
		shift += 7
	}

	return Uint(total), l
}

func (u Uint) Size() int {
	return len(uleb128(uint(u)))
}

func uleb128(v uint) []byte {
	b := make([]byte, 0, 16)
	for {
		c := uint8(v & 0x7f)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		b = append(b, c)
		if c&0x80 == 0 {
			break
		}
	}
	return b
}

// #######################################################
// String special

type String struct {
	Len byte
	S   []byte
}

func (s String) String() string {
	return string(s.S)
}

func (s String) Marshal() []byte {
	b := make([]byte, s.Len+1)
	b[0] = s.Len
	copy(b[1:], s.S)
	return b
}

func (s String) Unmarshal(b []byte) (any, int) {
	s.Len = b[0]
	s.S = make([]byte, b[0])
	copy(s.S, b[1:s.Len+1])
	return s, int(s.Len) + 1
}

func (s String) Size() int {
	return int(s.Len) + 1
}

// #######################################################
// Trigger for EnvSensor

type Trigger struct {
	Op    byte
	Value Uint
	Name  String
}

func (t Trigger) Marshal() []byte {
	varuint := t.Value.Marshal()
	b := make([]byte, 1+len(varuint)+t.Name.Size())
	b[0] = t.Op
	copy(b[1:], varuint)
	copy(b[1+len(varuint):], t.Name.Marshal())
	return b
}

func (t Trigger) Unmarshal(b []byte) (any, int) {
	t.Op = b[0]
	u, i := Uint(0).Unmarshal(b[1:])
	t.Value = u.(Uint)

	l := i + 1
	t.Name.Len = b[l]
	t.Name.S = make([]byte, b[l])
	copy(t.Name.S, b[l+1:])
	return t, l + int(t.Name.Len) + 1
}

func (t Trigger) Size() int {
	return 1 + t.Value.Size() + t.Name.Size()
}

// #######################################################
// Array

type Array[T arrayMarshaller] struct {
	Len byte
	Arr []T
}

func (a Array[T]) String() string {
	return fmt.Sprintf("%v", a.Arr)
}

func (a Array[T]) Marshal() []byte {
	var t T
	b := make([]byte, 1, t.Size()*int(a.Len)+1)
	b[0] = a.Len
	for _, v := range a.Arr {
		b = append(b, v.Marshal()...)
	}
	return b
}

func (a Array[T]) Unmarshal(b []byte) (any, int) {
	a.Len = b[0]
	a.Arr = make([]T, a.Len)
	offset := 1
	for i := byte(0); i < a.Len; i++ {
		item, plus := a.Arr[i].Unmarshal(b[offset:])
		a.Arr[i] = item.(T)
		offset += plus
	}
	return a, offset
}

func (a Array[T]) Size() int {
	var t T
	return 1 + int(a.Len)*t.Size()
}

// Complex structures

// #######################################################
// CmdBody that depends on DevType and Cmd

type CmdBody struct {
	Dev
	TimerCmdBody
	EnvSensorStatusCmdBody
	SwitchStatusCmdBody
}

func (b CmdBody) String() string {
	if !reflect.DeepEqual(b.Dev, Dev{}) {
		return fmt.Sprintf("\t\tDEVNAME: %s\n\t\tDEVPROPS: %v", b.Dev.DevName, b.Dev.DevProps)
	} else if !reflect.DeepEqual(b.TimerCmdBody, TimerCmdBody{}) {
		return fmt.Sprintf("%d", b.Timestamp)
	} else if !reflect.DeepEqual(b.EnvSensorStatusCmdBody, EnvSensorStatusCmdBody{}) {
		return fmt.Sprintf("%v", b.EnvSensorStatusCmdBody.values)
	} else if !reflect.DeepEqual(b.SwitchStatusCmdBody, SwitchStatusCmdBody{}) {
		return fmt.Sprintf("%d", b.SwitchStatusCmdBody)
	}
	return ""
}

// #######################################################
// Dev CmdBody

type Dev struct {
	DevName  String
	DevProps DevProps
}

// #######################################################
// DevProps

type DevProps struct {
	EnvSensorDevProps
	SwitchDevProps
}

func (p DevProps) String() string {
	if !reflect.DeepEqual(EnvSensorDevProps{}, p.EnvSensorDevProps) {
		return fmt.Sprintf("Sensors: %d, Triggers: %v", p.Sensor, p.Triggers)
	} else if !reflect.DeepEqual(p.SwitchDevProps, SwitchDevProps{}) {
		return fmt.Sprintf("NAMES: %s", p.SwitchDevProps.Names)
	}
	return ""
}

// #######################################################
// EnvSensorDevProps

type EnvSensorDevProps struct {
	Sensor   byte
	Triggers Array[Trigger]
}

func (e EnvSensorDevProps) Marshal() []byte {
	return append([]byte{e.Sensor}, e.Triggers.Marshal()...)
}

func (e EnvSensorDevProps) Unmarshal(b []byte) (any, int) {
	e.Sensor = b[0]
	triggers, l := e.Triggers.Unmarshal(b[1:])
	e.Triggers = triggers.(Array[Trigger])
	return e, l + 1
}

// #######################################################
// SwitchDevProps

type SwitchDevProps struct {
	Names Array[String]
}

func (p SwitchDevProps) Marshal() []byte {
	return p.Names.Marshal()
}

func (p SwitchDevProps) Unmarshal(b []byte) (any, int) {
	arr, l := p.Names.Unmarshal(b)
	p.Names = arr.(Array[String])
	return p, l
}

// #######################################################
// TimerCmdBody

type TimerCmdBody struct {
	Timestamp Uint
}

func (t TimerCmdBody) Unmarshal(b []byte) (any, int) {
	u, l := Uint(0).Unmarshal(b)
	t.Timestamp = u.(Uint)
	return t, l
}

// #######################################################
// EnvSensorStatusCmdBody

type EnvSensorStatusCmdBody struct {
	values Array[Uint]
}

func (es EnvSensorStatusCmdBody) Marshal() []byte {
	return es.values.Marshal()
}

func (es EnvSensorStatusCmdBody) Unmarshal(b []byte) (any, int) {
	arr, l := es.values.Unmarshal(b)
	es.values = arr.(Array[Uint])
	return es, l
}

// #######################################################
// CmdBody for Switch:Status

type SwitchStatusCmdBody struct {
	Pos byte
}

func (s SwitchStatusCmdBody) Marshal() []byte {
	return []byte{s.Pos}
}

func (s SwitchStatusCmdBody) Unmarshal(b []byte) (any, int) {
	s.Pos = b[0]
	return s, 1
}

// #######################################################
// Payload

type Payload struct {
	Src     Uint
	Dst     Uint
	Serial  Uint
	DevType byte
	Cmd     byte
	CmdBody CmdBody
}

func (p Payload) String() string {
	return fmt.Sprintf(
		`	SRC: %d
	DST: %d
	SERIAL: %d
	TYPE: %d
	CMD: %d
	CMDBODY:
%v`,
		p.Src, p.Dst, p.Serial, p.DevType, p.Cmd, p.CmdBody)
}

func (p Payload) marshal() (b []byte, err error) {
	b = append(b, p.Src.Marshal()...)
	b = append(b, p.Dst.Marshal()...)
	b = append(b, p.Serial.Marshal()...)
	b = append(b, p.DevType)
	b = append(b, p.Cmd)

	switch p.Cmd {
	case CmdWhoIsHere, CmdIAmHere: // except:
		b = append(b, p.CmdBody.Dev.DevName.Marshal()...)

		switch p.DevType {
		case TypeSmartHub, TypeSocket, TypeLamp:
			return

		case TypeSwitch:
			b = append(b, p.CmdBody.DevProps.SwitchDevProps.Marshal()...)
			return

		case TypeEnvSensor:
			b = append(b, p.CmdBody.DevProps.EnvSensorDevProps.Marshal()...)
			return

		case TypeClock:
			if p.Cmd == CmdIAmHere {
				return
			}
		}

	case CmdStatus: // except: SmartHub, Clock
		switch p.DevType {
		case TypeEnvSensor:
			b = append(b, p.CmdBody.EnvSensorStatusCmdBody.Marshal()...)
			return
		case TypeSwitch, TypeLamp, TypeSocket:
			b = append(b, p.CmdBody.SwitchStatusCmdBody.Marshal()...)
			return
		}

	case CmdGetStatus: // except: SmartHub, Clock
		switch p.DevType {
		case TypeEnvSensor, TypeSocket, TypeSwitch, TypeLamp:
			return
		}

	case CmdSetStatus: // except: SmartHub, Clock, Env, Socket
		switch p.DevType {
		case TypeSocket, TypeLamp:
			b = append(b, p.CmdBody.SwitchStatusCmdBody.Marshal()...)
			return

		}

	case CmdTick: // only Clock
		switch p.DevType {
		case TypeClock:
			b = append(b, p.CmdBody.TimerCmdBody.Timestamp.Marshal()...)
			return

		}
	}
	return nil, ErrPacketFormat
}

func (p Payload) unmarshal(b []byte) (pl any, l int, err error) {
	defer func() { pl = p }()

	src, off := Uint(0).Unmarshal(b)
	l += off
	p.Src = src.(Uint)

	dst, off := Uint(0).Unmarshal(b[l:])
	l += off
	p.Dst = dst.(Uint)

	serial, off := Uint(0).Unmarshal(b[l:])
	l += off
	p.Serial = serial.(Uint)

	p.DevType = b[l]
	p.Cmd = b[l+1]
	l += 2

	switch p.Cmd {
	case CmdWhoIsHere, CmdIAmHere:
		name, off := String{}.Unmarshal(b[l:])
		l += off
		p.CmdBody.DevName = name.(String)

		switch p.DevType {
		case TypeSmartHub, TypeSocket, TypeLamp:
			return

		case TypeSwitch:
			props, off := SwitchDevProps{}.Unmarshal(b[l:])
			l += off
			p.CmdBody.DevProps.SwitchDevProps = props.(SwitchDevProps)
			return

		case TypeEnvSensor:
			props, off := EnvSensorDevProps{}.Unmarshal(b[l:])
			l += off
			p.CmdBody.DevProps.EnvSensorDevProps = props.(EnvSensorDevProps)
			return

		case TypeClock:
			if p.Cmd == CmdIAmHere {
				return
			}
		}

	case CmdStatus:
		switch p.DevType {
		case TypeEnvSensor:
			props, off := EnvSensorStatusCmdBody{}.Unmarshal(b[l:])
			l += off
			p.CmdBody.EnvSensorStatusCmdBody = props.(EnvSensorStatusCmdBody)
			return
		case TypeSwitch, TypeLamp, TypeSocket:
			body, off := SwitchStatusCmdBody{}.Unmarshal(b[l:])
			l += off
			p.CmdBody.SwitchStatusCmdBody = body.(SwitchStatusCmdBody)
			return
		}

	case CmdGetStatus:
		switch p.DevType {
		case TypeEnvSensor, TypeSocket, TypeSwitch, TypeLamp:
			return
		}

	case CmdSetStatus:
		switch p.DevType {
		case TypeSocket, TypeLamp:
			body, off := SwitchStatusCmdBody{}.Unmarshal(b[l:])
			l += off
			p.CmdBody.SwitchStatusCmdBody = body.(SwitchStatusCmdBody)
			return

		}

	case CmdTick:
		switch p.DevType {
		case TypeClock:
			timestamp, off := TimerCmdBody{}.Unmarshal(b[l:])
			l += off
			p.CmdBody.TimerCmdBody = timestamp.(TimerCmdBody)
			return
		}

	}

	return nil, 0, ErrPacketFormat
}

func (p Payload) makeBytePacket() ([]byte, error) {
	b, err := p.marshal()
	if err != nil {
		return nil, fmt.Errorf("make packet error: %w", err)
	}

	bytePacket := make([]byte, len(b)+2)
	bytePacket[0] = byte(len(b))
	copy(bytePacket[1:], b)
	bytePacket[len(bytePacket)-1] = ComputeCRC8(b)

	return bytePacket, nil
}

// #######################################################
// Packet

type Packet struct {
	Length  byte
	Payload Payload
	Crc8    byte
}

func (p Packet) String() string {
	return fmt.Sprintf("-> Len: %d, crc8: %d\n\t--- Content ---\n%v", p.Length, p.Crc8, p.Payload)
}

// for test
func (p Packet) Encode() (string, error) {
	b, err := p.marshal()
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(append(b, ComputeCRC8(b[1:]))), nil
}

// for test
func (p Packet) Decode(s string) (Packet, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Packet{}, err
	}
	pack, _, err := p.unmarshal(b)
	if err != nil {
		return Packet{}, ErrPacketFormat
	}

	return pack.(Packet), nil
}

func (p Packet) marshal() ([]byte, error) {
	b, err := p.Payload.marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal packet error: %w", err)
	}

	return append([]byte{p.Length}, b...), nil
}

func (p Packet) unmarshal(b []byte) (any, int, error) {
	p.Length = b[0]
	l := 1
	pl, off, err := p.Payload.unmarshal(b[1 : len(b)-1])
	if err != nil {
		return nil, 0, fmt.Errorf("unmarshalling error: %w", err)
	}

	l += off
	p.Payload = pl.(Payload)
	p.Crc8 = b[l]
	if ComputeCRC8(b[1:l]) != p.Crc8 {
		return nil, 0, ErrCRC8
	}
	return p, l + 1, nil
}

//
//	---------------
//		Devices
//	---------------
//

type TypeGetter interface {
	GetType() byte
}

type AbstractDevice struct {
	TypeGetter
	Id          Uint
	Requested   bool
	LastRequest Uint
}

type Clock struct {
	AbstractDevice
	Time Uint
}

func NewClock() Clock {
	c := Clock{AbstractDevice: AbstractDevice{}}
	c.TypeGetter = c
	return c
}

func (Clock) GetType() byte {
	return TypeClock
}

type Lamp struct {
	AbstractDevice
	Position bool
}

func NewLamp() Lamp {
	l := Lamp{AbstractDevice: AbstractDevice{}}
	l.TypeGetter = l
	return l
}

func (Lamp) GetType() byte {
	return TypeLamp
}

type Socket struct {
	AbstractDevice
	Position bool
}

func NewSocket() Socket {
	s := Socket{AbstractDevice: AbstractDevice{}}
	s.TypeGetter = s
	return s
}

func (Socket) GetType() byte {
	return TypeSocket
}

type Switch struct {
	AbstractDevice
	Position bool
	Devices  []string
}

func NewSwitch() Switch {
	s := Switch{AbstractDevice: AbstractDevice{}}
	s.TypeGetter = s
	return s
}

func (Switch) GetType() byte {
	return TypeSwitch
}

type EnvSensor struct {
	AbstractDevice
	SensorMask byte
	Triggers   []Trigger
}

func NewEnvSensor() EnvSensor {
	e := EnvSensor{AbstractDevice: AbstractDevice{}}
	e.TypeGetter = e
	return e
}

func (EnvSensor) GetType() byte {
	return TypeEnvSensor
}

//
//	-------------
//	Packet Sender
//	-------------
//

func UnpackPacket(b []byte) (pp []Packet) {
	for i := 0; i != len(b); {
		p, l, err := Packet{}.unmarshal(b[i:])
		if err != nil {
			continue
		}

		i += l
		pp = append(pp, p.(Packet))
	}
	return
}

// Send sends a single payload, errors see SendPacket
func (p Payload) Send(host string) ([]Packet, error) {
	b, err := p.makeBytePacket()
	if err != nil {
		return nil, err
	}

	return SendPacket(host, base64.RawURLEncoding.EncodeToString(b))
}

func SendPayloads(host string, pp []Payload) ([]Packet, error) {
	bb := make([]byte, 0, 256*len(pp))
	for _, p := range pp {
		b, err := p.makeBytePacket()
		if err != nil {
			continue
		}

		bb = append(bb, b...)
	}

	return SendPacket(host, base64.RawURLEncoding.EncodeToString(bb))
}

// SendPacket sends a packet.
// The packet must be represented as base64 string.
// Possible errors: ErrHttp, ErrBadCode, ErrIO and std errors.
func SendPacket(host string, packet string) ([]Packet, error) {
	c := http.Client{}

	resp, err := c.Post(host, "text/plain", strings.NewReader(packet))
	if err != nil {
		return nil, ErrHttp
	}
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return nil, ErrBadCode
	}

	if resp.StatusCode == 204 {
		os.Exit(0)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrIO
	}

	unmarshalled, err := base64.RawURLEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	packets := UnpackPacket(unmarshalled)
	return packets, nil
}

func SendEmpty(host string) ([]Packet, error) {
	return SendPacket(host, "")
}

type DeviceMap struct {
	MapName map[Uint]string
	Device  map[string]AbstractDevice
}

type SwitchMap struct {
	MapName  map[Uint]string
	Switches map[string]Switch
}

type EnvSensorMap struct {
	MapName map[Uint]string
	Envs    map[string]EnvSensor
}

type Network struct {
	Clock    Clock        // the only Clock
	Switches SwitchMap    // all Switches
	Sensors  EnvSensorMap // all Sensors

	// all the Devices in the network including above except Clock
	Devices DeviceMap
}

// ClearExpired Удаляет просроченные пакеты и отключает устройства.
func ClearExpired() {
	for id, devName := range network.Devices.MapName {
		if a := network.Devices.Device[devName]; !a.Requested || currentTime-a.LastRequest <= MaxDifference {
			continue
		}

		devType := network.Devices.Device[devName].GetType()

		delete(network.Devices.MapName, id)
		delete(network.Devices.Device, devName)

		switch devType {
		case TypeEnvSensor:
			delete(network.Sensors.MapName, id)
			delete(network.Sensors.Envs, devName)
		case TypeSwitch:
			delete(network.Switches.MapName, id)
			delete(network.Switches.Switches, devName)
		}
	}
}

// packers
// //////////////////////////////////////////////////

func IAmHere() { // broadcast
	pl := Payload{
		Src:     address,
		Dst:     Broadcast,
		Serial:  serial,
		DevType: TypeSmartHub,
		Cmd:     CmdIAmHere,
		CmdBody: CmdBody{Dev: Dev{
			DevName: String{
				Len: byte(len(name)),
				S:   name,
			},
			DevProps: DevProps{},
		}},
	}
	serial++
	packetsToSend = append(packetsToSend, pl)
}

func GetStatus(d AbstractDevice) {
	pl := Payload{
		Src:     address,
		Dst:     d.Id,
		Serial:  serial,
		DevType: d.GetType(),
		Cmd:     CmdGetStatus,
		CmdBody: CmdBody{},
	}
	d.Requested = true
	d.LastRequest = currentTime
	network.Devices.Device[network.Devices.MapName[d.Id]] = d

	serial++
	packetsToSend = append(packetsToSend, pl)
}

func SetStatus(pos byte, d AbstractDevice) {
	pl := Payload{
		Src:     address,
		Dst:     d.Id,
		Serial:  serial,
		DevType: d.GetType(),
		Cmd:     CmdSetStatus,
		CmdBody: CmdBody{
			SwitchStatusCmdBody: SwitchStatusCmdBody{Pos: pos},
		},
	}
	d.Requested = true
	d.LastRequest = currentTime
	network.Devices.Device[network.Devices.MapName[d.Id]] = d

	serial++
	packetsToSend = append(packetsToSend, pl)
}

///////////////////////////////////////////////////

func main() {

	flag.Parse()
	if flag.NArg() < 2 {
		os.Exit(1)
	}

	networkUrl, err := url.Parse(flag.Arg(0))
	if err != nil {
		os.Exit(2)
	}

	a, err := strconv.ParseInt(flag.Arg(1), 16, 32)
	if err != nil {
		os.Exit(3)
	}
	address = Uint(a)

	if !(address >= 0 && address < 1<<14) {
		os.Exit(4)
	}

	CalculateTable()

	///////////////////////////////
	// First packet is WhoIsHere //
	///////////////////////////////

	firstPayload := Payload{
		Src:     address,
		Dst:     Broadcast,
		Serial:  FisrtPacketNumber,
		DevType: TypeSmartHub,
		Cmd:     CmdWhoIsHere,
		CmdBody: CmdBody{Dev: Dev{
			DevName: String{
				Len: byte(len(name)),
				S:   name,
			},
			DevProps: DevProps{},
		}},
	}

	pp, err := firstPayload.Send(networkUrl.String())
	if err != nil {
		if errors.Is(err, ErrHttp) || errors.Is(err, ErrBadCode) {
			os.Exit(ExitStatusHttpError)
		}
	}
	serial++

	startTimestamp = pp[0].Payload.CmdBody.Timestamp
	currentTime = startTimestamp

	packetQueue = append(make([]Packet, 0, 1024), pp[1:]...)

	/////////////////////////////
	// Вспомогательные функции //
	/////////////////////////////

	refreshActiveTime := func(devId Uint) {
		if dev, ok := network.Devices.Device[network.Devices.MapName[devId]]; ok {
			dev.LastRequest = currentTime
			network.Devices.Device[network.Devices.MapName[devId]] = dev
		}
	}

	// Проверяет, нужно ли игнорировать пакет
	shouldIgnore := func(devId Uint, cmd byte) bool {
		if cmd == CmdIAmHere {
			return false
		}

		_, ok := network.Devices.Device[network.Devices.MapName[devId]]
		return !ok
	}

MainLoop:
	for {
		if len(packetQueue) == 0 { // все пакеты обработаны

			// Отправляем новые пакеты
			if len(packetsToSend) > 0 {
				packets, err := SendPayloads(networkUrl.String(), packetsToSend)
				packetsToSend = []Payload{}
				if err != nil {
					if errors.Is(err, ErrHttp) || errors.Is(err, ErrBadCode) {
						os.Exit(ExitStatusHttpError)
					}
					continue MainLoop
				}

				packetQueue = append(packetQueue, packets...)
				continue MainLoop
			}

			// Отправляем пустое сообщение, если все устройства отключены
			if len(network.Devices.Device) == 0 {
				packets, err := SendEmpty(networkUrl.String())
				if err != nil {
					if errors.Is(err, ErrHttp) || errors.Is(err, ErrBadCode) {
						os.Exit(ExitStatusHttpError)
					}
					continue MainLoop
				}

				packetQueue = append(packetQueue, packets...)
				continue MainLoop
			}

			// Или отправляем GetStatus всем девайсам
			for _, v := range network.Devices.Device {
				GetStatus(v)
			}
			continue MainLoop
		}

		packet := packetQueue[0]      // обрабатываем текущий пакет
		packetQueue = packetQueue[1:] // уменьшаем очередь
		pl := packet.Payload          // для удобства берём Payload

		if shouldIgnore(pl.Src, pl.Cmd) {
			continue MainLoop
		}

		// обновляем
		refreshActiveTime(pl.Src)

		switch pl.Cmd { // Обработка команд
		case CmdWhoIsHere:
			IAmHere()
			fallthrough

		case CmdIAmHere:
			if pl.Cmd == CmdIAmHere && currentTime-startTimestamp > MaxDifference {
				continue MainLoop
			}
			var dev AbstractDevice

			switch pl.DevType {
			case TypeEnvSensor:
				env := NewEnvSensor()
				env.Id = pl.Src
				env.SensorMask = pl.CmdBody.DevProps.Sensor
				env.Triggers = pl.CmdBody.DevProps.Triggers.Arr

				dev = env.AbstractDevice

				network.Sensors.MapName[pl.Src] = string(pl.CmdBody.DevName.S)
				network.Sensors.Envs[string(pl.CmdBody.DevName.S)] = env

				GetStatus(dev)
			case TypeSwitch:
				sw := NewSwitch()
				sw.Id = pl.Src

				dev = sw.AbstractDevice
				sw.Devices = make([]string, 0, pl.CmdBody.DevProps.Names.Len)

				for _, v := range pl.CmdBody.DevProps.Names.Arr {
					sw.Devices = append(sw.Devices, string(v.S))
				}
				network.Switches.MapName[pl.Src] = string(pl.CmdBody.DevName.S)
				network.Switches.Switches[string(pl.CmdBody.DevName.S)] = sw

				GetStatus(dev)
			case TypeLamp:
				lamp := NewLamp()
				lamp.Id = pl.Src

				dev = lamp.AbstractDevice

			case TypeSocket:
				socket := NewSocket()
				socket.Id = pl.Src

				dev = socket.AbstractDevice

			case TypeClock:
				network.Clock = NewClock()
				network.Clock.Id = pl.Src

				network.Clock.Time = pl.CmdBody.Timestamp
				continue MainLoop
			}

			dev.LastRequest = currentTime
			network.Devices.MapName[pl.Src] = string(pl.CmdBody.DevName.S)
			network.Devices.Device[string(pl.CmdBody.DevName.S)] = dev

		case CmdStatus:
			dev := network.Devices.Device[network.Devices.MapName[pl.Src]]
			dev.Requested = false
			network.Devices.Device[network.Devices.MapName[pl.Src]] = dev

			switch pl.DevType {
			case TypeEnvSensor:
				props := network.Sensors.Envs[network.Sensors.MapName[pl.Src]]

				mask := props.SensorMask
				vals := split(mask, pl.CmdBody.EnvSensorStatusCmdBody.values.Arr)
				triggers := props.Triggers

				for _, tr := range triggers {
					if _, ok := network.Devices.Device[tr.Name.String()]; !ok {
						continue
					}
					action := tr.Op & TurnOnDevice
					comp := (tr.Op & CompareMoreThan) >> 1
					sens := (tr.Op & SensorMask) >> 2

					threshold := tr.Value
					devName := tr.Name.String()

					trig := false
					if mask&HasTemperatureSensor != 0 && sens == TemperatureSensor {
						trig = ((comp == 1) == (vals[TemperatureSensor] > threshold)) ||
							((comp == 0) == (vals[TemperatureSensor] < threshold))
					}
					if mask&HasHumiditySensor != 0 && sens == HumiditySensor {
						trig = ((comp == 1) == (vals[HumiditySensor] > threshold)) ||
							((comp == 0) == (vals[HumiditySensor] < threshold))
					}
					if mask&HasLightSensor != 0 && sens == LightSensor {
						trig = ((comp == 1) == (vals[LightSensor] > threshold)) ||
							((comp == 0) == (vals[LightSensor] < threshold))
					}
					if mask&HasPollutionSensor != 0 && sens == PollutionSensor {
						trig = ((comp == 1) == (vals[PollutionSensor] > threshold)) ||
							((comp == 0) == (vals[PollutionSensor] < threshold))
					}
					if trig {
						SetStatus(action, network.Devices.Device[devName])
					}
				}

			case TypeSwitch:
				sw := network.Switches.Switches[network.Switches.MapName[pl.Src]]
				pos := pl.CmdBody.Pos

				for _, s := range sw.Devices {
					dev, ok := network.Devices.Device[s]
					if !ok {
						continue
					}

					SetStatus(pos, dev)
				}

			case TypeLamp, TypeSocket:

			}

		case CmdTick:
			currentTime = pl.CmdBody.Timestamp

			// После обновления времени, проверяем, не "умерло" ли какое-нибудь устройство
			ClearExpired()
		}
	}
}

func CalculateTable() {
	gen := byte(0x1D)
	crcTable = make([]byte, 256)

	for dividend := range crcTable {
		curr := byte(dividend)
		for bit := 0; bit < 8; bit++ {
			if (curr & 0x80) != 0 {
				curr <<= 1
				curr ^= gen
			} else {
				curr <<= 1
			}
		}
		crcTable[dividend] = curr
	}
}

func ComputeCRC8(buf []byte) (crc byte) {
	for _, b := range buf {
		data := b ^ crc
		crc = crcTable[data]
	}
	return
}

func split(b byte, bb []Uint) (A [4]Uint) {
	i := 0
	if b&HasTemperatureSensor != 0 {
		A[TemperatureSensor] = bb[i]
		i++
	}
	if b&HasHumiditySensor != 0 {
		A[HumiditySensor] = bb[i]
		i++
	}
	if b&HasLightSensor != 0 {
		A[LightSensor] = bb[i]
		i++
	}
	if b&HasPollutionSensor != 0 {
		A[PollutionSensor] = bb[i]
		i++
	}
	return
}
