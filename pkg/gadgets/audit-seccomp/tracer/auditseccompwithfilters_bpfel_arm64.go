// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64
// +build arm64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type auditseccompwithfiltersContainer struct {
	ContainerId [256]int8
	Namespace   [256]int8
	Pod         [256]int8
	Container   [256]int8
}

type auditseccompwithfiltersEvent struct {
	Pid       uint64
	MntnsId   uint64
	Syscall   uint64
	Code      uint64
	Comm      [16]int8
	Container auditseccompwithfiltersContainer
}

// loadAuditseccompwithfilters returns the embedded CollectionSpec for auditseccompwithfilters.
func loadAuditseccompwithfilters() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_AuditseccompwithfiltersBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load auditseccompwithfilters: %w", err)
	}

	return spec, err
}

// loadAuditseccompwithfiltersObjects loads auditseccompwithfilters and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *auditseccompwithfiltersObjects
//     *auditseccompwithfiltersPrograms
//     *auditseccompwithfiltersMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadAuditseccompwithfiltersObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadAuditseccompwithfilters()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// auditseccompwithfiltersSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type auditseccompwithfiltersSpecs struct {
	auditseccompwithfiltersProgramSpecs
	auditseccompwithfiltersMapSpecs
}

// auditseccompwithfiltersSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type auditseccompwithfiltersProgramSpecs struct {
	KprobeAuditSeccomp *ebpf.ProgramSpec `ebpf:"kprobe__audit_seccomp"`
}

// auditseccompwithfiltersMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type auditseccompwithfiltersMapSpecs struct {
	Containers *ebpf.MapSpec `ebpf:"containers"`
	Events     *ebpf.MapSpec `ebpf:"events"`
	Filter     *ebpf.MapSpec `ebpf:"filter"`
	TmpEvent   *ebpf.MapSpec `ebpf:"tmp_event"`
}

// auditseccompwithfiltersObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadAuditseccompwithfiltersObjects or ebpf.CollectionSpec.LoadAndAssign.
type auditseccompwithfiltersObjects struct {
	auditseccompwithfiltersPrograms
	auditseccompwithfiltersMaps
}

func (o *auditseccompwithfiltersObjects) Close() error {
	return _AuditseccompwithfiltersClose(
		&o.auditseccompwithfiltersPrograms,
		&o.auditseccompwithfiltersMaps,
	)
}

// auditseccompwithfiltersMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadAuditseccompwithfiltersObjects or ebpf.CollectionSpec.LoadAndAssign.
type auditseccompwithfiltersMaps struct {
	Containers *ebpf.Map `ebpf:"containers"`
	Events     *ebpf.Map `ebpf:"events"`
	Filter     *ebpf.Map `ebpf:"filter"`
	TmpEvent   *ebpf.Map `ebpf:"tmp_event"`
}

func (m *auditseccompwithfiltersMaps) Close() error {
	return _AuditseccompwithfiltersClose(
		m.Containers,
		m.Events,
		m.Filter,
		m.TmpEvent,
	)
}

// auditseccompwithfiltersPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadAuditseccompwithfiltersObjects or ebpf.CollectionSpec.LoadAndAssign.
type auditseccompwithfiltersPrograms struct {
	KprobeAuditSeccomp *ebpf.Program `ebpf:"kprobe__audit_seccomp"`
}

func (p *auditseccompwithfiltersPrograms) Close() error {
	return _AuditseccompwithfiltersClose(
		p.KprobeAuditSeccomp,
	)
}

func _AuditseccompwithfiltersClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed auditseccompwithfilters_bpfel_arm64.o
var _AuditseccompwithfiltersBytes []byte
