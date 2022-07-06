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

type biotopInfoT struct {
	Mntnsid uint64
	Pid     uint32
	Rwflag  int32
	Major   int32
	Minor   int32
	Name    [16]int8
}

type biotopStartReqT struct {
	Ts      uint64
	DataLen uint64
}

type biotopValT struct {
	Bytes uint64
	Us    uint64
	Io    uint32
	_     [4]byte
}

type biotopWhoT struct {
	Mntnsid uint64
	Pid     uint32
	Name    [16]int8
	_       [4]byte
}

// loadBiotop returns the embedded CollectionSpec for biotop.
func loadBiotop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BiotopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load biotop: %w", err)
	}

	return spec, err
}

// loadBiotopObjects loads biotop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *biotopObjects
//     *biotopPrograms
//     *biotopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBiotopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBiotop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// biotopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type biotopSpecs struct {
	biotopProgramSpecs
	biotopMapSpecs
}

// biotopSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type biotopProgramSpecs struct {
	BlkAccountIoDone  *ebpf.ProgramSpec `ebpf:"blk_account_io_done"`
	BlkAccountIoStart *ebpf.ProgramSpec `ebpf:"blk_account_io_start"`
	BlkMqStartRequest *ebpf.ProgramSpec `ebpf:"blk_mq_start_request"`
}

// biotopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type biotopMapSpecs struct {
	Counts     *ebpf.MapSpec `ebpf:"counts"`
	MountNsSet *ebpf.MapSpec `ebpf:"mount_ns_set"`
	Start      *ebpf.MapSpec `ebpf:"start"`
	Whobyreq   *ebpf.MapSpec `ebpf:"whobyreq"`
}

// biotopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBiotopObjects or ebpf.CollectionSpec.LoadAndAssign.
type biotopObjects struct {
	biotopPrograms
	biotopMaps
}

func (o *biotopObjects) Close() error {
	return _BiotopClose(
		&o.biotopPrograms,
		&o.biotopMaps,
	)
}

// biotopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBiotopObjects or ebpf.CollectionSpec.LoadAndAssign.
type biotopMaps struct {
	Counts     *ebpf.Map `ebpf:"counts"`
	MountNsSet *ebpf.Map `ebpf:"mount_ns_set"`
	Start      *ebpf.Map `ebpf:"start"`
	Whobyreq   *ebpf.Map `ebpf:"whobyreq"`
}

func (m *biotopMaps) Close() error {
	return _BiotopClose(
		m.Counts,
		m.MountNsSet,
		m.Start,
		m.Whobyreq,
	)
}

// biotopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBiotopObjects or ebpf.CollectionSpec.LoadAndAssign.
type biotopPrograms struct {
	BlkAccountIoDone  *ebpf.Program `ebpf:"blk_account_io_done"`
	BlkAccountIoStart *ebpf.Program `ebpf:"blk_account_io_start"`
	BlkMqStartRequest *ebpf.Program `ebpf:"blk_mq_start_request"`
}

func (p *biotopPrograms) Close() error {
	return _BiotopClose(
		p.BlkAccountIoDone,
		p.BlkAccountIoStart,
		p.BlkMqStartRequest,
	)
}

func _BiotopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed biotop_bpfel_arm64.o
var _BiotopBytes []byte
