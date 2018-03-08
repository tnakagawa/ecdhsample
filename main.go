// main
package main

import (
	"fmt"
)

func main() {
	fmt.Println("Diffie-Hellman")
	dh := NewFFDHE2048()
	pri1, pub1 := dh.GenKeys()
	fmt.Printf("pri1:%x\n", pri1)
	fmt.Printf("pub1:%x\n", pub1)
	pri2, pub2 := dh.GenKeys()
	fmt.Printf("pri2:%x\n", pri2)
	fmt.Printf("pub2:%x\n", pub2)
	sha1 := dh.Mul(pri1, pub2)
	fmt.Printf("sha1:%x\n", sha1)
	sha2 := dh.Mul(pri2, pub1)
	fmt.Printf("sha2:%x\n", sha2)

	fmt.Println("Elliptic Curve")
	ec := NewSecp256k1()
	pri3 := ec.GenKey()
	fmt.Printf("pri3:%x\n", pri3)
	pub3 := ec.BaseMul(pri3)
	fmt.Printf("pub3:%x\n", pub3.SerializeCompressed())
	pri4 := ec.GenKey()
	fmt.Printf("pri4:%x\n", pri4)
	pub4 := ec.BaseMul(pri4)
	fmt.Printf("pub4:%x\n", pub4.SerializeCompressed())
	sha3 := ec.Mul(pub4, pri3)
	fmt.Printf("sha3:%x\n", sha3.SerializeCompressed())
	sha4 := ec.Mul(pub3, pri4)
	fmt.Printf("sha4:%x\n", sha4.SerializeCompressed())
}
