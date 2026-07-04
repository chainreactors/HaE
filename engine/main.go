package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/template"
	"github.com/chainreactors/utils/parsers"
	"gopkg.in/yaml.v3"
)

// ═══════════════════════════════════════════════════════════
//  Proton API — regex matching engine
// ═══════════════════════════════════════════════════════════

const (
	FlagFullMatch      = 1
	FlagSkipValidation = 2
	FlagBlockScan      = 4
)

var (
	scanners   = make(map[int]*file.Scanner)
	scannersMu sync.RWMutex
	nextHandle int64
)

//export ProtonVersion
func ProtonVersion() *C.char {
	return C.CString("0.3.0")
}

//export ProtonLoadTemplate
func ProtonLoadTemplate(data *C.char, length C.int) C.int {
	if data == nil || length <= 0 {
		return 0
	}
	goData := C.GoBytes(unsafe.Pointer(data), length)
	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{}}

	var tmpls []*template.Template
	for _, doc := range splitYAMLDocs(goData) {
		tmpl, err := parseTemplate(doc, execOpts)
		if err != nil || tmpl == nil {
			continue
		}
		tmpls = append(tmpls, tmpl)
	}
	if len(tmpls) == 0 {
		return 0
	}

	var inputs []file.Rule
	for _, tmpl := range tmpls {
		inputs = append(inputs, file.Rule{
			ID: tmpl.Id, Name: tmpl.Info.Name, Severity: tmpl.Info.Severity,
			Requests: tmpl.RequestsFile,
		})
	}

	scanner := file.NewScanner(inputs, execOpts)
	handle := int(atomic.AddInt64(&nextHandle, 1))
	scannersMu.Lock()
	scanners[handle] = scanner
	scannersMu.Unlock()
	return C.int(handle)
}

//export ProtonFindAll
func ProtonFindAll(handle C.int, data unsafe.Pointer, dataLen C.int, label *C.char, flags C.int) *C.char {
	if data == nil || dataLen <= 0 {
		return C.CString("[]")
	}
	scannersMu.RLock()
	s, ok := scanners[int(handle)]
	scannersMu.RUnlock()
	if !ok {
		return C.CString("[]")
	}

	goData := C.GoBytes(data, dataLen)
	goLabel := ""
	if label != nil {
		goLabel = C.GoString(label)
	}

	var opts []file.FindOption
	f := int(flags)
	if f&FlagFullMatch != 0 {
		opts = append(opts, file.WithFullMatch())
	}
	if f&FlagSkipValidation != 0 {
		opts = append(opts, file.WithSkipValidation())
	}
	if f&FlagBlockScan != 0 {
		opts = append(opts, file.WithBlockScan())
	}

	var findings []file.Finding
	for _, group := range s.Groups {
		findings = append(findings, s.FindAll(goData, goLabel, group, opts...)...)
	}

	if findings == nil {
		return C.CString("[]")
	}
	result, _ := json.Marshal(findings)
	return C.CString(string(result))
}

//export ProtonFreeScanner
func ProtonFreeScanner(handle C.int) {
	scannersMu.Lock()
	delete(scanners, int(handle))
	scannersMu.Unlock()
}

//export ProtonFreeString
func ProtonFreeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// ═══════════════════════════════════════════════════════════
//  Fingers API — fingerprint detection (fingerprinthub only)
// ═══════════════════════════════════════════════════════════

var (
	fpEngines   = make(map[int]*fingerprinthub.FingerPrintHubEngine)
	fpEnginesMu sync.RWMutex
)

//export FingersVersion
func FingersVersion() *C.char {
	return C.CString("0.1.0")
}

//export FingersNewEngine
func FingersNewEngine() C.int {
	eng, err := fingerprinthub.NewFingerPrintHubEngine(
		resources.FingerprinthubWebData,
		resources.FingerprinthubServiceData,
	)
	if err != nil {
		return 0
	}

	handle := int(atomic.AddInt64(&nextHandle, 1))
	fpEnginesMu.Lock()
	fpEngines[handle] = eng
	fpEnginesMu.Unlock()
	return C.int(handle)
}

//export FingersDetect
func FingersDetect(handle C.int, data unsafe.Pointer, dataLen C.int) *C.char {
	if data == nil || dataLen <= 0 {
		return C.CString("[]")
	}
	fpEnginesMu.RLock()
	eng, ok := fpEngines[int(handle)]
	fpEnginesMu.RUnlock()
	if !ok {
		return C.CString("[]")
	}

	goData := C.GoBytes(data, dataLen)
	frameworks := eng.WebMatch(goData)
	if len(frameworks) == 0 {
		return C.CString("[]")
	}

	type fwOut struct {
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		From    string `json:"from,omitempty"`
		Tags    string `json:"tags,omitempty"`
	}
	var out []fwOut
	for _, fw := range frameworks {
		out = append(out, fwOut{
			Name:    fw.Name,
			Version: fw.Version,
			From:    fw.From.String(),
			Tags:    strings.Join(fw.Tags, ","),
		})
	}
	result, _ := json.Marshal(out)
	return C.CString(string(result))
}

//export FingersFreeEngine
func FingersFreeEngine(handle C.int) {
	fpEnginesMu.Lock()
	delete(fpEngines, int(handle))
	fpEnginesMu.Unlock()
}

// ─── Helpers ───

// force linker to keep these packages
var _ = operators.WordsMatcher
var _ = parsers.Result{}

func splitYAMLDocs(data []byte) [][]byte {
	parts := strings.Split(string(data), "\n---")
	result := make([][]byte, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if len(trimmed) > 0 {
			result = append(result, []byte(trimmed))
		}
	}
	return result
}

func parseTemplate(data []byte, execOpts *protocols.ExecuterOptions) (*template.Template, error) {
	var tmpl template.Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, err
	}
	if len(tmpl.RequestsFile) == 0 {
		return nil, nil
	}
	if err := tmpl.Compile(execOpts); err != nil {
		return nil, err
	}
	return &tmpl, nil
}

func main() {}
