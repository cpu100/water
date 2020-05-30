// +build darwin,go1.11

package water

import "syscall"

func setNonBlock(fd syscall.Handle) error {
	return syscall.SetNonblock(fd, true)
}
