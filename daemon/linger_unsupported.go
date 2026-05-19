//go:build !linux

package daemon

// CheckLinger reports systemd linger status. Non-Linux daemon backends do not
// use systemd linger, so callers should treat it as already satisfied.
func CheckLinger() (enabled bool, user string) {
	return true, ""
}
