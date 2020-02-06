// borrowed from
//  https://github.com/snapcore/snapd/blob/master/osutil/chattr.go
//  https://yourbasic.org/golang/bitmask-flag-set-clear/
package xattr

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

)

type flagsName struct {
	flag      int32
	shortName *byte
	longName  *byte
}

var flagsArray []flagsName = []flagsName{
	{int32(1), &[]byte("s\x00")[0], &[]byte("Secure_Deletion\x00")[0]},
	{int32(2), &[]byte("u\x00")[0], &[]byte("Undelete\x00")[0]},
	{int32(8), &[]byte("S\x00")[0], &[]byte("Synchronous_Updates\x00")[0]},
	{int32(65536), &[]byte("D\x00")[0], &[]byte("Synchronous_Directory_Updates\x00")[0]},
	{int32(16), &[]byte("i\x00")[0], &[]byte("Immutable\x00")[0]},
	{int32(32), &[]byte("a\x00")[0], &[]byte("Append_Only\x00")[0]},
	{int32(64), &[]byte("d\x00")[0], &[]byte("No_Dump\x00")[0]},
	{int32(128), &[]byte("A\x00")[0], &[]byte("No_Atime\x00")[0]},
	{int32(4), &[]byte("c\x00")[0], &[]byte("Compression_Requested\x00")[0]},
	{int32(16384), &[]byte("j\x00")[0], &[]byte("Journaled_Data\x00")[0]},
	{int32(4096), &[]byte("I\x00")[0], &[]byte("Indexed_directory\x00")[0]},
	{int32(32768), &[]byte("t\x00")[0], &[]byte("No_Tailmerging\x00")[0]},
	{int32(131072), &[]byte("T\x00")[0], &[]byte("Top_of_Directory_Hierarchies\x00")[0]},
	{int32(524288), &[]byte("e\x00")[0], &[]byte("Extents\x00")[0]},
	{int32(262144), &[]byte("h\x00")[0], &[]byte("Huge_file\x00")[0]},
	{int32(0), nil, nil}}

func Has(b int32, flag flagsName) bool    { return b&flag.flag != 0 }


func ioctl(f *os.File, request uintptr, attrp *int32) error {
	argp := uintptr(unsafe.Pointer(attrp))
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), request, argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}

	return nil
}


func PrintFlags(objFlags int32) error {
	for _,flag := range flagsArray {
		if Has(objFlags,flag) {
			fmt.Printf("%s", string(*flag.shortName))
		}else {
			fmt.Printf("%s", "-")
		}
	}
	return nil
}

/// GetAttr retrieves the attributes of a file on a linux filesystem
func GetAttr(f *os.File) (int32, error) {

	attr := int32(-1)
	if runtime.GOARCH == "amd64" {
		err := ioctl(f, uintptr(0x80086601), &attr)
		return attr, err
	} else {
		err := ioctl(f, uintptr(0x80046601), &attr)
		return attr, err
	}
}