package utils

import (
	"HHELand"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"math"
	"math/bits"
	"strings"
)

// HandleError checks the error and throws a panic if the error isn't nil
func HandleError(err error) {
	if err != nil {
		fmt.Printf("|-> Error: %s\n", err.Error())
		panic("=== Panic\n ")
	}
}

// Uint64ToHex converts a vector of uint64 elements to hexadecimal values
// and print them
func Uint64ToHex(data []uint64) {
	hexData := make([]string, len(data))
	for i, v := range data {
		hexData[i] = fmt.Sprintf("%#x", v)
	}
	fmt.Println(hexData)
}

// ByteToHexMod converts a vector of byte elements to hexadecimal values
// with respect to a modulus, and print them
func ByteToHexMod(data []byte, modulus uint64) string {
	// Convert bytes to uint64 and take modulus
	result := make([]uint64, len(data)/8)
	for i := 0; i < len(data)/8; i++ {
		result[i] = uint64(data[i*8]) |
			uint64(data[i*8+1])<<8 |
			uint64(data[i*8+2])<<16 |
			uint64(data[i*8+3])<<24 |
			uint64(data[i*8+4])<<32 |
			uint64(data[i*8+5])<<40 |
			uint64(data[i*8+6])<<48 |
			uint64(data[i*8+7])<<56

		result[i] %= modulus
	}

	// Convert uint64 to hexadecimal string
	hexValues := make([]string, len(result))
	for i, v := range result {
		hexValues[i] = fmt.Sprintf("%#x", v)
	}

	// Join hexadecimal values into a string
	return strings.Join(hexValues, ", ")
}

// ScaleUp scale up the f by p
// and return the integer value
func ScaleUp(f float64, scaleFactor float64) uint64 {
	return uint64(math.Round(f * scaleFactor))
}

// ScaleDown scale an integer value x by p
// and return the floating point value
func ScaleDown(x uint64, scaleFactor float64) float64 {
	return float64(x) / scaleFactor
}

// GenTestVector generates random values for test vectors
func GenTestVector(n int, modulus uint64) {
	nonces := make([][]byte, n)
	for i := 0; i < n; i++ {
		nonces[i] = make([]byte, 8)
		_, err := rand.Read(nonces[i])
		if err != nil {
			panic(err)
		}
	}
	fmt.Print("{")
	for i := 0; i < n; i++ {
		result := ByteToHexMod(nonces[i], modulus)
		fmt.Printf("%s, ", result)
		if (i+1)%4 == 0 {
			fmt.Printf("\n")
		}
	}
	fmt.Print("}\n")
}

// RandomFloatDataGen to generate a matrix of floating point numbers between 0 and 1
func RandomFloatDataGen(col int, row int) (data [][]float64) {
	data = make([][]float64, row)
	for s := 0; s < row; s++ {
		data[s] = make([]float64, col)
		for i := 0; i < col; i++ {
			data[s][i] = sampling.RandFloat64(0, 1)
		}
	}
	return
}

// CreateMatrix Helper function to create a matrix for uint64
func CreateMatrix(rows int, cols int) [][]uint64 {
	mat := make([][]uint64, rows)
	for i := range mat {
		mat[i] = make([]uint64, cols)
	}
	return mat
}

// CreateMatrixFloat Helper function to create a matrix for float64
func CreateMatrixFloat(rows int, cols int) [][]float64 {
	mat := make([][]float64, rows)
	for i := range mat {
		mat[i] = make([]float64, cols)
	}
	return mat
}

// RandUint64 return a random value between 0 and 0xFFFFFFFFFFFFFFFF
func RandUint64() uint64 {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint64(b)
}

// RandFloat64 returns a random float between min and max
func RandFloat64(min, max float64) float64 {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	f := float64(binary.BigEndian.Uint64(b)) / 1.8446744073709552e+19
	return min + f*(max-min)
}

// RandComplex128 returns a random complex with the real and imaginary part between min and max
func RandComplex128(min, max float64) complex128 {
	return complex(RandFloat64(min, max), RandFloat64(min, max))
}

// EqualSliceUint64 checks the equality between two uint64 slices.
func EqualSliceUint64(a, b []uint64) (v bool) {
	v = true
	for i := range a {
		v = v && (a[i] == b[i])
	}
	return
}

// EqualSliceInt64 checks the equality between two int64 slices.
func EqualSliceInt64(a, b []int64) (v bool) {
	v = true
	for i := range a {
		v = v && (a[i] == b[i])
	}
	return
}

// EqualSliceUint8 checks the equality between two uint8 slices.
func EqualSliceUint8(a, b []uint8) (v bool) {
	v = true
	for i := range a {
		v = v && (a[i] == b[i])
	}
	return
}

// IsInSliceUint64 checks if x is in slice.
func IsInSliceUint64(x uint64, slice []uint64) (v bool) {
	for i := range slice {
		v = v || (slice[i] == x)
	}
	return
}

// IsInSliceInt checks if x is in slice.
func IsInSliceInt(x int, slice []int) (v bool) {
	for i := range slice {
		v = v || (slice[i] == x)
	}
	return
}

// MinUint64 returns the minimum value of the input of uint64 values.
func MinUint64(a, b uint64) (r uint64) {
	if a <= b {
		return a
	}
	return b
}

// MinInt returns the minimum value of the input of int values.
func MinInt(a, b int) (r int) {
	if a <= b {
		return a
	}
	return b
}

// MaxUint64 returns the maximum value of the input of uint64 values.
func MaxUint64(a, b uint64) (r uint64) {
	if a >= b {
		return a
	}
	return b
}

// MaxInt returns the maximum value of the input of int values.
func MaxInt(a, b int) (r int) {
	if a >= b {
		return a
	}
	return b
}

// MaxFloat64 returns the maximum value of the input slice of float64 values.
func MaxFloat64(a, b float64) (r float64) {
	if a >= b {
		return a
	}
	return b
}

// MaxSliceUint64 returns the maximum value of the input slice of uint64 values.
func MaxSliceUint64(slice []uint64) (max uint64) {
	for i := range slice {
		max = MaxUint64(max, slice[i])
	}
	return
}

// BitReverse64 returns the bit-reverse value of the input value, within a context of 2^bitLen.
func BitReverse64(index, bitLen uint64) uint64 {
	return bits.Reverse64(index) >> (64 - bitLen)
}

// HammingWeight64 returns the hammingweight if the input value.
func HammingWeight64(x uint64) uint64 {
	x -= (x >> 1) & 0x5555555555555555
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
	return ((x * 0x0101010101010101) & 0xffffffffffffffff) >> 56
}

// AllDistinct returns true if all elements in s are distinct, and false otherwise.
func AllDistinct(s []uint64) bool {
	m := make(map[uint64]struct{}, len(s))
	for _, si := range s {
		if _, exists := m[si]; exists {
			return false
		}
		m[si] = struct{}{}
	}
	return true
}

// RotateUint64Slice returns a new slice corresponding to s rotated by k positions to the left.
func RotateUint64Slice(s []uint64, k int) []uint64 {
	if k == 0 || len(s) == 0 {
		return s
	}
	r := k % len(s)
	if r < 0 {
		r = r + len(s)
	}
	ret := make([]uint64, len(s), len(s))
	copy(ret[:len(s)-r], s[r:])
	copy(ret[len(s)-r:], s[:r])
	return ret
}

// RotateUint64Slots returns a new slice corresponding to s where each half of the slice
// have been rotated by k positions to the left.
func RotateUint64Slots(s []uint64, k int) []uint64 {
	ret := make([]uint64, len(s), len(s))
	slots := len(s) >> 1
	copy(ret[:slots], RotateUint64Slice(s[:slots], k))
	copy(ret[slots:], RotateUint64Slice(s[slots:], k))
	return ret
}

// RotateComplex128Slice returns a new slice corresponding to s rotated by k positions to the left.
func RotateComplex128Slice(s []complex128, k int) []complex128 {
	if k == 0 || len(s) == 0 {
		return s
	}
	r := k % len(s)
	if r < 0 {
		r = r + len(s)
	}
	ret := make([]complex128, len(s), len(s))
	copy(ret[:len(s)-r], s[r:])
	copy(ret[len(s)-r:], s[:r])
	return ret
}

// ResizeSlice resize the old slice
func ResizeSlice(oldSlice HHELand.Block, newLen uint64) (newSlice HHELand.Block) {
	l := uint64(len(oldSlice))
	if newLen == l {
		newSlice = oldSlice
	} else if newLen > l {
		newSlice = append(oldSlice, make(HHELand.Block, newLen-l)...)
	} else {
		newSlice = oldSlice[:newLen]
	}
	return
}

// Reverse to reverse a slice
func Reverse(slice HHELand.Block) {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
}

// RotateSlice to rotate a slice by a given offset
func RotateSlice(slice HHELand.Block, offset uint64) {
	l := len(slice)
	if l == 0 {
		return
	}

	// Normalize offset to be within the slice's length
	offset %= uint64(l)
	// Rotate the slice elements
	Reverse(slice[:offset])
	Reverse(slice[offset:])
	Reverse(slice)
}
