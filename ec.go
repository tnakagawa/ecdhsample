// ec
package main

import (
	"crypto/rand"
	"math/big"
)

type ECP struct {
	X *big.Int
	Y *big.Int
}

func (ecp *ECP) Serialize() []byte {
	var bs []byte
	bs = append(bs, 0x04)
	x := ecp.X.Bytes()
	if len(x) < 32 {
		tmp := make([]byte, 32-len(x))
		bs = append(bs, tmp...)
	}
	bs = append(bs, x...)
	y := ecp.Y.Bytes()
	if len(y) < 32 {
		tmp := make([]byte, 32-len(y))
		bs = append(bs, tmp...)
	}
	bs = append(bs, y...)
	return bs
}

func (ecp *ECP) SerializeCompressed() []byte {
	var bs []byte
	if ecp.Y.Bit(0) == 0 {
		bs = append(bs, 0x02)
	} else {
		bs = append(bs, 0x03)
	}
	x := ecp.X.Bytes()
	if len(x) < 32 {
		tmp := make([]byte, 32-len(x))
		bs = append(bs, tmp...)
	}
	bs = append(bs, x...)
	return bs
}

type EC struct {
	P *big.Int
	A *big.Int
	B *big.Int
	G *ECP
	N *big.Int
}

func NewSecp256k1() *EC {
	ec := new(EC)
	ec.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	ec.A, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000000", 16)
	ec.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	ec.G = new(ECP)
	ec.G.X, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	ec.G.Y, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	ec.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	return ec
}

func (ec *EC) GenKey() *big.Int {
	bs := make([]byte, 32)
	rand.Read(bs)
	pri := new(big.Int).Mod(new(big.Int).SetBytes(bs), ec.N)
	return pri
}

func (ec *EC) Add(p, q *ECP) *ECP {
	// https://ja.wikipedia.org/wiki/%E6%A5%95%E5%86%86%E6%9B%B2%E7%B7%9A
	var s *big.Int
	r := new(ECP)
	if p.X.Cmp(q.X) != 0 {
		// s = (Yp-Yq)/(Xp-Xq)
		s = new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Sub(p.Y, q.Y),
				new(big.Int).ModInverse(
					new(big.Int).Sub(p.X, q.X), ec.P)),
			ec.P)
		// Xr = s^2 - Xp - Xq
		r.X = new(big.Int).Mod(
			new(big.Int).Sub(
				new(big.Int).Sub(
					new(big.Int).Exp(s, big.NewInt(2), ec.P),
					p.X), q.X),
			ec.P)
	} else {
		// s = (3Xp^2-p)/(2Yp)
		s = new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Sub(
					new(big.Int).Mul(big.NewInt(3),
						new(big.Int).Exp(p.X, big.NewInt(2), ec.P)),
					ec.A),
				new(big.Int).ModInverse(
					new(big.Int).Mul(big.NewInt(2), p.Y), ec.P)),
			ec.P)
		// Xr = s^2 - 2Xp
		r.X = new(big.Int).Mod(
			new(big.Int).Sub(
				new(big.Int).Exp(s, big.NewInt(2), ec.P),
				new(big.Int).Mul(big.NewInt(2), p.X)),
			ec.P)
	}
	// Yr = -(Yp + s(Xr-Xp))
	r.Y = new(big.Int).Mod(new(big.Int).Neg(
		new(big.Int).Add(p.Y, new(big.Int).Mul(s, new(big.Int).Sub(r.X, p.X)))),
		ec.P)
	return r
}

func (ec *EC) Mul(p *ECP, n *big.Int) *ECP {
	nn := new(big.Int).Mod(n, ec.N)
	if nn.BitLen() == 0 {
		return nil
	}
	xx := new(ECP)
	xx.X = new(big.Int).SetBytes(p.X.Bytes())
	xx.Y = new(big.Int).SetBytes(p.Y.Bytes())
	var sum *ECP
	for i := 0; i < nn.BitLen(); i++ {
		if nn.Bit(i) == 1 {
			if sum == nil {
				sum = new(ECP)
				sum.X = new(big.Int).SetBytes(xx.X.Bytes())
				sum.Y = new(big.Int).SetBytes(xx.Y.Bytes())
			} else {
				sum = ec.Add(sum, xx)
			}
		}
		xx = ec.Add(xx, xx)
	}
	return sum
}

func (ec *EC) BaseMul(n *big.Int) *ECP {
	return ec.Mul(ec.G, n)
}
