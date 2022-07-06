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

// loadBindsnoop returns the embedded CollectionSpec for bindsnoop.
func loadBindsnoop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BindsnoopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bindsnoop: %w", err)
	}

	return spec, err
}

// loadBindsnoopObjects loads bindsnoop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *bindsnoopObjects
//     *bindsnoopPrograms
//     *bindsnoopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBindsnoopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBindsnoop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bindsnoopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bindsnoopSpecs struct {
	bindsnoopProgramSpecs
	bindsnoopMapSpecs
}

// bindsnoopSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bindsnoopProgramSpecs struct {
	Ipv4BindEntry *ebpf.ProgramSpec `ebpf:"ipv4_bind_entry"`
	Ipv4BindExit  *ebpf.ProgramSpec `ebpf:"ipv4_bind_exit"`
	Ipv6BindEntry *ebpf.ProgramSpec `ebpf:"ipv6_bind_entry"`
	Ipv6BindExit  *ebpf.ProgramSpec `ebpf:"ipv6_bind_exit"`
}

// bindsnoopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bindsnoopMapSpecs struct {
	Events     *ebpf.MapSpec `ebpf:"events"`
	MountNsSet *ebpf.MapSpec `ebpf:"mount_ns_set"`
	Ports      *ebpf.MapSpec `ebpf:"ports"`
	Sockets    *ebpf.MapSpec `ebpf:"sockets"`
}

// bindsnoopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBindsnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type bindsnoopObjects struct {
	bindsnoopPrograms
	bindsnoopMaps
}

func (o *bindsnoopObjects) Close() error {
	return _BindsnoopClose(
		&o.bindsnoopPrograms,
		&o.bindsnoopMaps,
	)
}

// bindsnoopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBindsnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type bindsnoopMaps struct {
	Events     *ebpf.Map `ebpf:"events"`
	MountNsSet *ebpf.Map `ebpf:"mount_ns_set"`
	Ports      *ebpf.Map `ebpf:"ports"`
	Sockets    *ebpf.Map `ebpf:"sockets"`
}

func (m *bindsnoopMaps) Close() error {
	return _BindsnoopClose(
		m.Events,
		m.MountNsSet,
		m.Ports,
		m.Sockets,
	)
}

// bindsnoopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBindsnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type bindsnoopPrograms struct {
	Ipv4BindEntry *ebpf.Program `ebpf:"ipv4_bind_entry"`
	Ipv4BindExit  *ebpf.Program `ebpf:"ipv4_bind_exit"`
	Ipv6BindEntry *ebpf.Program `ebpf:"ipv6_bind_entry"`
	Ipv6BindExit  *ebpf.Program `ebpf:"ipv6_bind_exit"`
}

func (p *bindsnoopPrograms) Close() error {
	return _BindsnoopClose(
		p.Ipv4BindEntry,
		p.Ipv4BindExit,
		p.Ipv6BindEntry,
		p.Ipv6BindExit,
	)
}

func _BindsnoopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bindsnoop_bpfel_arm64.o
var _BindsnoopBytes []byte
