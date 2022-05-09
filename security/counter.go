// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package security

/*
TS 33.501 6.4.3.1
 COUNT (32 bits) := 0x00 || NAS COUNT (24 bits)
 NAS COUNT (24 bits) := NAS OVERFLOW (16 bits) || NAS SQN (8 bits)
*/
type Count struct {
	Count uint32 `json:"count,omitempty" bson:"count,omitempty"`
}

func (counter *Count) maskTo24Bits() {
	counter.Count &= 0x00ffffff
}

func (counter *Count) Set(overflow uint16, sqn uint8) {
	counter.SetOverflow(overflow)
	counter.SetSQN(sqn)
}

func (counter *Count) Get() uint32 {
	counter.maskTo24Bits()
	return counter.Count
}

func (counter *Count) AddOne() {
	counter.Count++
	counter.maskTo24Bits()
}

func (counter *Count) SQN() uint8 {
	return uint8(counter.Count & 0x000000ff)
}

func (counter *Count) SetSQN(sqn uint8) {
	counter.Count = (counter.Count & 0xffffff00) | uint32(sqn)
}

func (counter *Count) Overflow() uint16 {
	return uint16((counter.Count & 0x00ffff00) >> 8)
}

func (counter *Count) SetOverflow(overflow uint16) {
	counter.Count = (counter.Count & 0xff0000ff) | (uint32(overflow) << 8)
}
