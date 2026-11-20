//go:build !linux && !darwin && !windows

package pin

// diskFree is not measured on this system, so the metric is left out.
func diskFree(string) (uint64, bool) { return 0, false }
