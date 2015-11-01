package netu

// Taken from https://github.com/xiezhenye/harp/blob/master/src/arp/arp.go#L53
func Htons(n uint16) uint16 {
	var (
		high uint16 = n >> 8
		ret  uint16 = n<<8 + high
	)
	return ret
}
