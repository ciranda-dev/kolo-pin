//go:build linux || darwin

package pin

import "golang.org/x/sys/unix"

// diskFree returns the bytes free to unprivileged users on the filesystem of dir.
func diskFree(dir string) (uint64, bool) {
	var st unix.Statfs_t
	if unix.Statfs(dir, &st) != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true
}
