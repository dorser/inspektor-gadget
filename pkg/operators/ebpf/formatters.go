// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpfoperator

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/annotations"
)

const (
	enumTargetNameAnnotation        = "ebpf.formatter.enum"
	enumBitfieldSeparatorAnnotation = "ebpf.formatter.bitfield.separator"
)

func byteSliceAsUint64(in []byte, signed bool, ds datasource.DataSource) uint64 {
	if signed {
		switch len(in) {
		case 1:
			return uint64(int8(in[0]))
		case 2:
			return uint64(int16(ds.ByteOrder().Uint16(in)))
		case 4:
			return uint64(int32(ds.ByteOrder().Uint32(in)))
		case 8:
			return uint64(int64(ds.ByteOrder().Uint64(in)))
		}
	}

	switch len(in) {
	case 1:
		return uint64(in[0])
	case 2:
		return uint64(ds.ByteOrder().Uint16(in))
	case 4:
		return uint64(ds.ByteOrder().Uint32(in))
	case 8:
		return uint64(ds.ByteOrder().Uint64(in))
	}

	return 0
}

func (i *ebpfInstance) initEnumFormatter(gadgetCtx operators.GadgetContext) error {
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		i.logger.Warnf("Kernel BTF information not available. Enums won't be resolved to strings")
	}

	for _, ds := range gadgetCtx.GetDataSources() {
		var formatters []func(ds datasource.DataSource, data datasource.Data) error

		for name, enum := range i.enums {
			in := ds.GetField(name)
			if in == nil {
				continue
			}
			in.SetHidden(true, false)

			if btfSpec != nil {
				kernelEnum := &btf.Enum{}
				if err = btfSpec.TypeByName(enum.Name, &kernelEnum); err == nil {
					// Use kernel enum if found
					enum = kernelEnum
				}
			}

			targetName, err := annotations.GetTargetNameFromAnnotation(i.logger, "enum", in, enumTargetNameAnnotation)
			if err != nil {
				i.logger.Warnf("Failed to get target name for enum field %q: %v", in.Name(), err)
				continue
			}

			out, err := ds.AddField(targetName, api.Kind_String)
			if err != nil {
				return err
			}

			var formatter func(ds datasource.DataSource, data datasource.Data) error

			isBitField := strings.HasSuffix(enum.Name, "_set")
			if isBitField {
				separator := in.Annotations()[enumBitfieldSeparatorAnnotation]
				if separator == "" {
					separator = "|"
				}

				formatter = func(ds datasource.DataSource, data datasource.Data) error {
					inBytes := in.Get(data)
					val := byteSliceAsUint64(inBytes, enum.Signed, ds)

					var arr []string
					for _, v := range enum.Values {
						if val&v.Value == v.Value {
							arr = append(arr, v.Name)
						}
					}
					out.PutString(data, strings.Join(arr, separator))
					return nil
				}
			} else {
				formatter = func(ds datasource.DataSource, data datasource.Data) error {
					// TODO: lookup table?
					inBytes := in.Get(data)
					val := byteSliceAsUint64(inBytes, enum.Signed, ds)
					for _, v := range enum.Values {
						if val == v.Value {
							out.Set(data, []byte(v.Name))
							return nil
						}
					}
					out.Set(data, []byte("UNKNOWN"))
					return nil
				}
			}

			formatters = append(formatters, formatter)
		}

		if len(formatters) > 0 {
			i.formatters[ds] = formatters
		}
	}

	return nil
}

func (i *ebpfInstance) initFormatters(gadgetCtx operators.GadgetContext) error {
	if err := i.initEnumFormatter(gadgetCtx); err != nil {
		return fmt.Errorf("initializing enum formatter: %w", err)
	}

	return nil
}
