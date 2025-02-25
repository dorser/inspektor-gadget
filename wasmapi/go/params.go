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

package api

import (
	"errors"
	_ "unsafe"
)

//go:wasmimport env getParamValue
//go:linkname getParamValue getParamValue
func getParamValue(key uint64, dst uint64) uint32

func GetParamValue(key string, maxSize uint64) (string, error) {
	dst := make([]byte, maxSize)

	k := uint64(stringToBufPtr(key))
	ret := getParamValue(k, uint64(bytesToBufPtr(dst)))
	if ret == 1 {
		return "", errors.New("error getting param value")
	}

	return fromCString(dst), nil
}
