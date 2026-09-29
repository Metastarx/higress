// Copyright (c) 2025 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"testing"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/test"
	"github.com/stretchr/testify/require"
)

// attachedRouteName is the route that the domain/route rule below attaches the
// plugin to. Matching this route makes the wasm-go rule matcher return the
// rule-level config, which is what sets HmacAuthConfig.RuleSet to true in
// config.ParseOverrideRuleConfig.
const attachedRouteName = "hmac-attached-route"

// failClosedConsumers is the consumer set shared by these regression tests.
func failClosedConsumers() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "c1", "access_key": "ak1", "secret_key": "sk1"},
		{"name": "c2", "access_key": "ak2", "secret_key": "sk2"},
	}
}

// attachRule builds the `_rules_` payload that attaches the plugin to
// attachedRouteName. When allow is nil the rule omits the `allow` key entirely,
// which is exactly the configuration that used to fail open.
func attachRule(allow []string) []map[string]interface{} {
	rule := map[string]interface{}{
		"_match_route_": []string{attachedRouteName},
	}
	if allow != nil {
		rule["allow"] = allow
	}
	return []map[string]interface{}{rule}
}

// TestFailClosed_AttachedRuleWithoutAllow_RejectsUnsignedRequest reproduces the
// original defect: the plugin is attached to a matched route rule that has no
// `allow` entry and no global_auth is configured. Before the fix the handler
// returned ActionContinue and the unsigned request was proxied upstream.
func TestFailClosed_AttachedRuleWithoutAllow_RejectsUnsignedRequest(t *testing.T) {
	test.RunTest(t, func(t *testing.T) {
		host, status := test.NewTestHost(createConfig(failClosedConsumers(), map[string]interface{}{
			"_rules_": attachRule(nil),
		}))
		defer host.Reset()
		require.Equal(t, types.OnPluginStartStatusOK, status)
		require.NoError(t, host.SetRouteName(attachedRouteName))

		action := host.CallOnHttpRequestHeaders([][2]string{
			{":authority", "example.com"}, {":path", "/p"}, {":method", "GET"},
		})
		require.Equal(t, types.ActionContinue, action)

		resp := host.GetLocalResponse()
		require.NotNil(t, resp, "an attached rule with no allow list must fail closed")
		require.Equal(t, uint32(401), resp.StatusCode)
		require.Contains(t, string(resp.Data), "no consumer is allowed")

		_, ok := findHeader(host.GetRequestHeaders(), "X-Mse-Consumer")
		require.False(t, ok, "a rejected request must not be attributed to a consumer")
	})
}

// TestFailClosed_AttachedRuleWithoutAllow_RejectsValidSignature makes sure the
// fail-closed decision does not depend on the signature being present or valid:
// a rule that authorizes no consumer rejects every caller, signed or not.
func TestFailClosed_AttachedRuleWithoutAllow_RejectsValidSignature(t *testing.T) {
	test.RunTest(t, func(t *testing.T) {
		host, status := test.NewTestHost(createConfig(failClosedConsumers(), map[string]interface{}{
			"_rules_": attachRule(nil),
		}))
		defer host.Reset()
		require.Equal(t, types.OnPluginStartStatusOK, status)
		require.NoError(t, host.SetRouteName(attachedRouteName))

		d := gmt()
		ah := authHeaderRequestTargetDate("ak1", "sk1", "hmac-sha256", "GET", "/p", d)
		action := host.CallOnHttpRequestHeaders([][2]string{
			{":authority", "example.com"}, {":path", "/p"}, {":method", "GET"},
			{"authorization", ah}, {"date", d},
		})
		require.Equal(t, types.ActionContinue, action)

		resp := host.GetLocalResponse()
		require.NotNil(t, resp)
		require.Equal(t, uint32(401), resp.StatusCode)
		require.Contains(t, string(resp.Data), "no consumer is allowed")
	})
}

// TestFailClosed_AttachedRuleWithoutAllow_GlobalAuthMatrix covers the three
// global_auth values for an attached rule with an empty allow list. Only
// global_auth == true keeps normal signature verification in play; the unset
// and disabled cases must fail closed instead of letting the request through.
func TestFailClosed_AttachedRuleWithoutAllow_GlobalAuthMatrix(t *testing.T) {
	enabled := true
	disabled := false
	tests := []struct {
		name        string
		globalAuth  *bool
		wantMessage string
	}{
		{"global_auth unset", nil, "no consumer is allowed"},
		{"global_auth false", &disabled, "no consumer is allowed"},
		{"global_auth true enforces credentials", &enabled, "missing Authorization header"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			test.RunTest(t, func(t *testing.T) {
				extra := map[string]interface{}{"_rules_": attachRule(nil)}
				if tt.globalAuth != nil {
					extra["global_auth"] = *tt.globalAuth
				}
				host, status := test.NewTestHost(createConfig(failClosedConsumers(), extra))
				defer host.Reset()
				require.Equal(t, types.OnPluginStartStatusOK, status)
				require.NoError(t, host.SetRouteName(attachedRouteName))

				action := host.CallOnHttpRequestHeaders([][2]string{
					{":authority", "example.com"}, {":path", "/p"}, {":method", "GET"},
				})
				require.Equal(t, types.ActionContinue, action)
				resp := host.GetLocalResponse()
				require.NotNil(t, resp)
				require.Equal(t, uint32(401), resp.StatusCode)
				require.Contains(t, string(resp.Data), tt.wantMessage)
			})
		})
	}
}

// TestAttachedRuleWithAllow_RequiresAuthentication keeps the non-empty allow
// path honest: an attached rule that lists consumers still rejects a request
// without credentials, and the rejection comes from the normal HMAC flow.
func TestAttachedRuleWithAllow_RequiresAuthentication(t *testing.T) {
	test.RunTest(t, func(t *testing.T) {
		host, status := test.NewTestHost(createConfig(failClosedConsumers(), map[string]interface{}{
			"_rules_": attachRule([]string{"c1"}),
		}))
		defer host.Reset()
		require.Equal(t, types.OnPluginStartStatusOK, status)
		require.NoError(t, host.SetRouteName(attachedRouteName))

		action := host.CallOnHttpRequestHeaders([][2]string{
			{":authority", "example.com"}, {":path", "/p"}, {":method", "GET"},
		})
		require.Equal(t, types.ActionContinue, action)

		resp := host.GetLocalResponse()
		require.NotNil(t, resp)
		require.Equal(t, uint32(401), resp.StatusCode)
		require.Contains(t, string(resp.Data), "missing Authorization header")
	})
}

// TestAttachedRuleWithAllow_AcceptsListedConsumer is the happy path: a valid
// signature for a consumer that is present in the rule-level allow list is
// accepted and tagged with the consumer name.
func TestAttachedRuleWithAllow_AcceptsListedConsumer(t *testing.T) {
	test.RunTest(t, func(t *testing.T) {
		host, status := test.NewTestHost(createConfig(failClosedConsumers(), map[string]interface{}{
			"_rules_": attachRule([]string{"c1"}),
		}))
		defer host.Reset()
		require.Equal(t, types.OnPluginStartStatusOK, status)
		require.NoError(t, host.SetRouteName(attachedRouteName))

		d := gmt()
		ah := authHeaderRequestTargetDate("ak1", "sk1", "hmac-sha256", "GET", "/p", d)
		action := host.CallOnHttpRequestHeaders([][2]string{
			{":authority", "example.com"}, {":path", "/p"}, {":method", "GET"},
			{"authorization", ah}, {"date", d},
		})
		require.Equal(t, types.ActionContinue, action)
		require.Nil(t, host.GetLocalResponse())

		got, ok := findHeader(host.GetRequestHeaders(), "X-Mse-Consumer")
		require.True(t, ok)
		require.Equal(t, "c1", got)
	})
}

// TestAttachedRuleWithAllow_RejectsConsumerOutsideAllowList verifies the
// membership check is enforced independently of global_auth: the signature is
// valid for c1 but the rule only allows c2.
func TestAttachedRuleWithAllow_RejectsConsumerOutsideAllowList(t *testing.T) {
	test.RunTest(t, func(t *testing.T) {
		host, status := test.NewTestHost(createConfig(failClosedConsumers(), map[string]interface{}{
			"_rules_": attachRule([]string{"c2"}),
		}))
		defer host.Reset()
		require.Equal(t, types.OnPluginStartStatusOK, status)
		require.NoError(t, host.SetRouteName(attachedRouteName))

		d := gmt()
		ah := authHeaderRequestTargetDate("ak1", "sk1", "hmac-sha256", "GET", "/p", d)
		host.CallOnHttpRequestHeaders([][2]string{
			{":authority", "example.com"}, {":path", "/p"}, {":method", "GET"},
			{"authorization", ah}, {"date", d},
		})

		resp := host.GetLocalResponse()
		require.NotNil(t, resp)
		require.Equal(t, uint32(401), resp.StatusCode)
		require.Contains(t, string(resp.Data), `consumer 'c1' is not allowed`)
	})
}

// TestAttachedRuleWithAllow_UnknownConsumerRejected covers an unknown keyId:
// it must be rejected before the allow list is ever consulted.
func TestAttachedRuleWithAllow_UnknownConsumerRejected(t *testing.T) {
	test.RunTest(t, func(t *testing.T) {
		host, status := test.NewTestHost(createConfig(failClosedConsumers(), map[string]interface{}{
			"_rules_": attachRule([]string{"c1"}),
		}))
		defer host.Reset()
		require.Equal(t, types.OnPluginStartStatusOK, status)
		require.NoError(t, host.SetRouteName(attachedRouteName))

		d := gmt()
		ah := authHeaderRequestTargetDate("unknown", "sk", "hmac-sha256", "GET", "/p", d)
		host.CallOnHttpRequestHeaders([][2]string{
			{":authority", "example.com"}, {":path", "/p"}, {":method", "GET"},
			{"authorization", ah}, {"date", d},
		})

		resp := host.GetLocalResponse()
		require.NotNil(t, resp)
		require.Equal(t, uint32(401), resp.StatusCode)
		require.Contains(t, string(resp.Data), "Invalid keyId")
	})
}

// TestNotAttached_GlobalAuthFalse_SkipsAuthentication is the one case that must
// still skip authentication: global_auth is explicitly disabled and the request
// is served by a route that never attached the plugin.
func TestNotAttached_GlobalAuthFalse_SkipsAuthentication(t *testing.T) {
	test.RunTest(t, func(t *testing.T) {
		host, status := test.NewTestHost(createConfig(failClosedConsumers(), map[string]interface{}{
			"global_auth": false,
			"_rules_":     attachRule(nil),
		}))
		defer host.Reset()
		require.Equal(t, types.OnPluginStartStatusOK, status)
		// A different route means the rule does not match this request.
		require.NoError(t, host.SetRouteName("some-other-route"))

		action := host.CallOnHttpRequestHeaders([][2]string{
			{":authority", "example.com"}, {":path", "/p"}, {":method", "GET"},
		})
		require.Equal(t, types.ActionContinue, action)
		require.Nil(t, host.GetLocalResponse())
	})
}

// TestNotAttached_GlobalAuthUnset_StillAuthenticates pins down the preserved
// behaviour for global_auth unset: requests that match no rule fall back to the
// global config, which keeps authentication enabled.
func TestNotAttached_GlobalAuthUnset_StillAuthenticates(t *testing.T) {
	test.RunTest(t, func(t *testing.T) {
		host, status := test.NewTestHost(createConfig(failClosedConsumers(), map[string]interface{}{
			"_rules_": attachRule(nil),
		}))
		defer host.Reset()
		require.Equal(t, types.OnPluginStartStatusOK, status)
		require.NoError(t, host.SetRouteName("some-other-route"))

		host.CallOnHttpRequestHeaders([][2]string{
			{":authority", "example.com"}, {":path", "/p"}, {":method", "GET"},
		})

		resp := host.GetLocalResponse()
		require.NotNil(t, resp, "global_auth unset keeps authentication enabled for unmatched requests")
		require.Equal(t, uint32(401), resp.StatusCode)
		require.Contains(t, string(resp.Data), "missing Authorization header")
	})
}

// TestGlobalAuthTrue_NotAttached_StillAuthenticates confirms that enabling
// global_auth keeps enforcing signatures even for routes without their own rule.
func TestGlobalAuthTrue_NotAttached_StillAuthenticates(t *testing.T) {
	test.RunTest(t, func(t *testing.T) {
		host, status := test.NewTestHost(createConfig(failClosedConsumers(), map[string]interface{}{
			"global_auth": true,
			"_rules_":     attachRule(nil),
		}))
		defer host.Reset()
		require.Equal(t, types.OnPluginStartStatusOK, status)
		require.NoError(t, host.SetRouteName("some-other-route"))

		host.CallOnHttpRequestHeaders([][2]string{
			{":authority", "example.com"}, {":path", "/p"}, {":method", "GET"},
		})

		resp := host.GetLocalResponse()
		require.NotNil(t, resp)
		require.Equal(t, uint32(401), resp.StatusCode)
		require.Contains(t, string(resp.Data), "missing Authorization header")
	})
}
