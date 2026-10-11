// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

// A data source's options are read from datasources.yaml and survive the
// JSON encoding that carries the configuration from the client to the
// engine.
func TestDataSourceOptions(t *testing.T) {
	var dsc DataSourceConfig
	if err := yaml.Unmarshal([]byte(`
datasources:
  - name: Prospeo
    options:
      max_emails_per_domain: 10
      min_remaining_credits: 500
    creds:
      account:
        apikey: abc
  - name: CertSpotter
`), &dsc); err != nil {
		t.Fatal(err)
	}

	c := NewConfig()
	c.DataSrcConfigs = &dsc
	b, err := c.JSON()
	if err != nil {
		t.Fatal(err)
	}
	got := NewConfig()
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatal(err)
	}

	ds := got.GetDataSourceConfig("prospeo")
	if v := ds.IntOption("max_emails_per_domain", 25); v != 10 {
		t.Errorf("max_emails_per_domain = %d, want 10", v)
	}
	if v := ds.IntOption("min_remaining_credits", 0); v != 500 {
		t.Errorf("min_remaining_credits = %d, want 500", v)
	}
	if v := got.GetDataSourceConfig("CertSpotter").IntOption("max_emails_per_domain", 25); v != 25 {
		t.Errorf("unset option = %d, want the default 25", v)
	}
	if v := got.GetDataSourceConfig("missing").IntOption("x", 7); v != 7 {
		t.Errorf("missing source = %d, want the default 7", v)
	}
}
