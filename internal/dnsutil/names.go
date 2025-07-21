package dnsutil

// fast, ascii-only, case-insensitive equality check
func EqualNames(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var ac, bc byte
	for i := 0; i < len(a); i++ {
		ac = a[i]
		bc = b[i]
		if ac == bc {
			continue
		}
		if ac > bc {
			ac, bc = bc, ac
		}
		if ac >= 'A' && ac <= 'Z' && bc == ac+'a'-'A' {
			continue
		}
		return false
	}
	return true
}
