package nockchain

import (
	"errors"
	"math/big"
	"strconv"
	"strings"
)

// NicksPerNock is the binary denomination used on native Nockchain.
const NicksPerNock uint64 = 1 << 16

// FormatNocks renders nicks exactly, without floating-point rounding.
func FormatNocks(nicks uint64) string {
	whole := strconv.FormatUint(nicks/NicksPerNock, 10)
	remainder := nicks % NicksPerNock
	if remainder == 0 {
		return whole
	}
	fraction := strconv.FormatUint(remainder*152587890625, 10)
	fraction = strings.Repeat("0", 16-len(fraction)) + fraction
	return whole + "." + strings.TrimRight(fraction, "0")
}

// ParseNocks accepts a nonnegative decimal amount that represents whole nicks.
// It rejects exponents, signs, whitespace, overflow, and sub-nick precision.
func ParseNocks(text string) (uint64, error) {
	if len(text) == 0 || len(text) > 40 {
		return 0, errors.New("invalid NOCK amount")
	}
	parts := strings.Split(text, ".")
	if len(parts) > 2 || len(parts[0]) == 0 {
		return 0, errors.New("invalid NOCK amount")
	}
	for _, part := range parts {
		if len(part) == 0 {
			return 0, errors.New("invalid NOCK amount")
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return 0, errors.New("invalid NOCK amount")
			}
		}
	}
	if len(parts) == 2 && len(parts[1]) > 16 {
		return 0, errors.New("NOCK decimal precision exceeds 16 places")
	}
	v, ok := new(big.Rat).SetString(text)
	if !ok {
		return 0, errors.New("invalid NOCK amount")
	}
	v.Mul(v, new(big.Rat).SetInt(new(big.Int).SetUint64(NicksPerNock)))
	if !v.IsInt() || !v.Num().IsUint64() {
		return 0, errors.New("NOCK amount is outside the whole-nick range")
	}
	return v.Num().Uint64(), nil
}
