// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package port_prefilter

import (
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

// The pipeline runs a handler whose plugin the config does not name only
// when CheckTransformations matches the handler's Transforms.
func TestPrefilterTransformsMatchIPAddressAll(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Transformations = map[string]*config.Transformation{
		"IPAddress->ALL": {From: "ipaddress", To: "all"},
	}
	if _, err := cfg.CheckTransformations("IPAddress", prefilterTransforms...); err != nil {
		t.Errorf("IPAddress->ALL does not enable Port-Prefilter: %v", err)
	}
}

// Excluding Service discovery from IPAddress->ALL also turns the scan off,
// as it does for Protocol-Probes and HTTP-Probes.
func TestPrefilterTransformsFollowServiceExclude(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Transformations = map[string]*config.Transformation{
		"IPAddress->ALL": {From: "ipaddress", To: "all", Exclude: []string{"service"}},
	}
	if _, err := cfg.CheckTransformations("IPAddress", prefilterTransforms...); err == nil {
		t.Error("IPAddress->ALL excluding Service still enables Port-Prefilter")
	}
}
