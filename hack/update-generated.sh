#!/bin/bash

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
CODEGEN_PKG=${CODEGEN_PKG:-$(cd "${SCRIPT_ROOT}"; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../code-generator)}

chmod +x "${CODEGEN_PKG}/generate-groups.sh"
chmod +x "${CODEGEN_PKG}/generate-internal-groups.sh"

"${CODEGEN_PKG}/generate-internal-groups.sh" \
  all \
  github.com/upmc-enterprises/elasticsearch-operator/pkg/client \
  github.com/upmc-enterprises/elasticsearch-operator/pkg/apis \
  github.com/upmc-enterprises/elasticsearch-operator/apis \
  elasticsearchoperator:v1  \
  --output-base "${SCRIPT_ROOT}/gen/internal" \
  --go-header-file "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt" \
  "$@"

"${CODEGEN_PKG}/generate-groups.sh" \
  all \
  github.com/upmc-enterprises/elasticsearch-operator/pkg/client \
  github.com/upmc-enterprises/elasticsearch-operator/pkg/apis \
  elasticsearchoperator:v1  \
  --output-base "${SCRIPT_ROOT}/gen/groups" \
  --go-header-file "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt" \
  "$@"
