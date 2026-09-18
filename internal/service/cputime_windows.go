package service

import (
	"time"

	"golang.org/x/sys/windows"
)

// processCPUSeconds returns total user+system CPU seconds consumed by the
// current process (Windows implementation via GetProcessTimes).
func processCPUSeconds() (float64, error) {
	handle := windows.CurrentProcess()
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	kernelSec := filetimeToSeconds(kernel)
	userSec := filetimeToSeconds(user)
	return kernelSec + userSec, nil
}

func filetimeToSeconds(ft windows.Filetime) float64 {
	nsec := (int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)) * 100
	return float64(nsec) / float64(time.Second.Nanoseconds())
}
