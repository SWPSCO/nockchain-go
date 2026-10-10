package nockchain

import "math/big"

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func encodeBase58(data []byte) string {
	zeroes := 0
	for zeroes < len(data) && data[zeroes] == 0 {
		zeroes++
	}
	n := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	rem := new(big.Int)
	out := make([]byte, 0, len(data)*138/100+1)
	for n.Sign() != 0 {
		n.QuoRem(n, base, rem)
		out = append(out, alphabet[rem.Int64()])
	}
	for i := 0; i < zeroes; i++ {
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
func decodeBase58(text string) []byte {
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range []byte(text) {
		index := -1
		for i := 0; i < len(alphabet); i++ {
			if alphabet[i] == c {
				index = i
				break
			}
		}
		if index < 0 {
			return nil
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(index)))
	}
	zeroes := 0
	for zeroes < len(text) && text[zeroes] == '1' {
		zeroes++
	}
	return append(make([]byte, zeroes), n.Bytes()...)
}
