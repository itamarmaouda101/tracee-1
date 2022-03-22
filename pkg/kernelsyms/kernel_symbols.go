package kernelsyms

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

/*
 * this package is to support a kernel-malware detection and especially rootkits.
 * in addition it gives tracee the ability to hold all the known kernel symbols
 *
 * the KernelSymbolTable type holds map of all the kernel symbols with a ke y which is the kernel object owner and the name with undercase between them
 * which means that symbolMap looks like [objectOwner_objectname{SymbolData}, objectOwner_objectname{SymbolData}, etc...]
 * the key naming is because sometimes kernel symbols can have the same name or the same address which prevents to key the map with only one of them
 *
 */

type KernelSymbolTable struct {
	symbolMap   map[string]KernelSymbol
	initialized bool
	mtx         sync.RWMutex // protecting both update and delete entries
}

type KernelSymbol struct {
	Name    string
	Type    string
	Address uint64
	Owner   string
}

func (k *KernelSymbolTable) IsInTextSegment(addr uint64) (bool, error) {
	if !k.initialized {
		return false, fmt.Errorf("KernelSymbolTable symbols map isnt initialized\n")
	}
	stext, err := k.GetSymbolByName("system", "_stext")
	if err != nil {
		return false, err
	}
	etext, err := k.GetSymbolByName("system", "_etext")
	if err != nil {
		return false, err
	}
	if (addr >= stext.Address) && (addr < etext.Address) {
		return true, nil
	}
	return false, nil
}

//GetSymbolByAddr returns a symbol by a given address
func (k *KernelSymbolTable) GetSymbolByAddr(addr uint64) (KernelSymbol, error) {
	k.mtx.Lock()
	defer k.mtx.Unlock()
	for _, Symbol := range k.symbolMap {
		if Symbol.Address == addr {
			return Symbol, nil
		}
	}
	return KernelSymbol{}, fmt.Errorf("symbol not found")
}

//GetSymbolByName returns a symbol by a given name and owner
func (k *KernelSymbolTable) GetSymbolByName(owner string, name string) (KernelSymbol, error) {
	k.mtx.Lock()
	defer k.mtx.Unlock()
	key := fmt.Sprintf("%s_%s", owner, name)
	symbol, exist := k.symbolMap[key]
	if exist {
		return symbol, nil
	}
	return KernelSymbol{}, fmt.Errorf("symbol not found")
}

// NewKernelSymbolsMap Initiate the kernel symbol map
// Note: the key of the map is the symbol owner and the symbol name (with undercase between them)
func NewKernelSymbolsMap() (KernelSymbolTable, error) {
	var KernelSymbols = KernelSymbolTable{}
	KernelSymbols.symbolMap = make(map[string]KernelSymbol)
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return KernelSymbols, fmt.Errorf("Could not open /proc/kallsyms")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) < 3 {
			continue
		}
		symbolAddr, err := strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			continue
		}
		symbolName := line[2]
		symbolOwner := "system"
		if len(line) > 3 {
			symbolOwner = line[3]
		}
		symbolKey := fmt.Sprintf("%s_%s", symbolOwner, symbolName)
		KernelSymbols.symbolMap[symbolKey] = KernelSymbol{line[2], line[1], symbolAddr, symbolOwner}
	}
	KernelSymbols.initialized = true
	return KernelSymbols, nil
}