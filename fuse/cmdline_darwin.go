//go:build darwin

package fuse

/*
#include <libproc.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func getExePath(pid uint32) (string, error) {
	buf := (*C.char)(C.malloc(C.PROC_PIDPATHINFO_MAXSIZE))
	if buf == nil {
		return "", fmt.Errorf("malloc failed")
	}
	defer C.free(unsafe.Pointer(buf))

	ret := C.proc_pidpath(C.int(pid), unsafe.Pointer(buf), C.PROC_PIDPATHINFO_MAXSIZE)
	if ret <= 0 {
		return "", fmt.Errorf("proc_pidpath failed")
	}
	return C.GoString(buf), nil
}
