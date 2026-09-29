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
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"hmac-auth-apisix/config"
)

const (
	// 认证涉及的请求头
	authorizationHeader = "Authorization"
	dateHeader          = "Date"
	digestHeader        = "Digest"
	// 认证通过后在请求头 consumerHeader 中添加消费者信息
	consumerHeader = "X-Mse-Consumer"

	signaturePrefix       = "Signature "
	errorResponseTemplate = `{"message":"client request can't be validated: %s"}`
)

var (
	// 使用正则表达式匹配 key="value" 格式
	fieldRegex = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

func main() {}

func init() {
	wrapper.SetCtx(
		"hmac-auth-apisix",
		wrapper.ParseOverrideConfig(config.ParseGlobalConfig, config.ParseOverrideRuleConfig),
		wrapper.ProcessRequestHeaders(onHttpRequestHeaders),
		wrapper.ProcessRequestBody(onHttpRequestBody),
	)
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, cfg config.HmacAuthConfig) types.Action {
	var (
		// noAllow 为 true 表示当前生效的配置没有声明任何被授权的消费者：
		// - 全局配置不会读取 allow（见 config.ParseGlobalConfig），所以恒为 true；
		// - domain/route 规则未写 allow 字段时同样为 true（见 config.ParseOverrideRuleConfig）。
		// ruleSet 为 true 表示当前请求命中了显式挂载本插件的 domain/route 规则
		// （由 config.ParseOverrideRuleConfig 置位），而不是只拿到全局配置。
		noAllow            = len(cfg.Allow) == 0
		globalAuthNoSet    = cfg.GlobalAuth == nil
		globalAuthSetTrue  = !globalAuthNoSet && *cfg.GlobalAuth
		globalAuthSetFalse = !globalAuthNoSet && !*cfg.GlobalAuth
		ruleSet            = cfg.RuleSet
	)

	// 只有当插件对当前请求完全未生效时才跳过认证：显式关闭了全局鉴权（global_auth == false），
	// 并且当前请求没有命中任何挂载本插件的规则。此时既没有规则要求鉴权，也没有消费者名单可校验，
	// 直接放行是安全的。
	if globalAuthSetFalse && !ruleSet && noAllow {
		log.Info("authorization is not required")
		ctx.DontReadRequestBody()
		return types.ActionContinue
	}

	// 请求命中了显式挂载本插件的规则（ruleSet），但该规则没有配置 allow 列表，
	// 说明这条规则没有授权任何消费者。此时必须拒绝请求（fail closed）：否则任意未签名的
	// 请求都会被直接转发到上游，绕过 HMAC 签名校验。global_auth == true 时全局鉴权仍然
	// 生效，会继续走下面的正常校验流程，不受此分支影响。
	if ruleSet && noAllow && !globalAuthSetTrue {
		log.Warnf("plugin is attached to the matched rule but no consumer is allowed; rejecting request")
		return sendUnauthorizedResponse("no consumer is allowed")
	}
	// 提取 HMAC 字段和消费者信息
	hmacParams, err := retrieveHmacFieldsAndConsumer(cfg)
	if err != nil {
		// 只有在完全无法解析认证信息时才考虑匿名消费者
		if cfg.AnonymousConsumer != "" {
			ctx.DontReadRequestBody()
			setConsumerHeader(cfg.AnonymousConsumer)
			return types.ActionContinue
		}
		return sendUnauthorizedResponse(err.Error())
	}
	log.Debugf("HMAC params extracted: keyId=%s, algorithm=%s, signature=%s, headers=%v, consumerName=%s",
		hmacParams.KeyId, hmacParams.Algorithm, hmacParams.Signature, hmacParams.Headers, hmacParams.ConsumerName)

	// allow 列表只在当前生效的配置显式声明了它时才生效，与是否开启 global_auth 无关：
	// 只要配置了 allow，即使签名校验通过，消费者也必须属于该列表，否则同样拒绝。
	// 全局配置不会读取 allow，因此这里的 cfg.Allow 实际只可能来自匹配到的规则。
	if !noAllow && !contains(cfg.Allow, hmacParams.ConsumerName) {
		log.Warnf("consumer %q is not allowed", hmacParams.ConsumerName)
		return sendUnauthorizedResponse("consumer '" + hmacParams.ConsumerName + "' is not allowed")
	}

	// 校验时间偏差
	if cfg.ClockSkew > 0 {
		if err := validateClockSkew(cfg.ClockSkew); err != nil {
			return sendUnauthorizedResponse(err.Error())
		}
	}

	// 验证算法是否允许
	if !contains(cfg.AllowedAlgorithms, hmacParams.Algorithm) {
		return sendUnauthorizedResponse("Invalid algorithm")
	}

	// 验证签名头
	if len(cfg.SignedHeaders) > 0 {
		if len(hmacParams.Headers) == 0 {
			return sendUnauthorizedResponse("headers missing")
		}

		// 检查所有配置的签名头是否都在签名中
		signedHeadersMap := make(map[string]bool)
		for _, header := range hmacParams.Headers {
			signedHeadersMap[strings.ToLower(header)] = true
		}

		for _, requiredHeader := range cfg.SignedHeaders {
			lowerRequiredHeader := strings.ToLower(requiredHeader)
			if !signedHeadersMap[lowerRequiredHeader] {
				return sendUnauthorizedResponse("expected header \"" + requiredHeader + "\" missing in signing")
			}
		}
	}

	// 验证 HMAC 签名
	if err := validateSignature(hmacParams, cfg); err != nil {
		return sendUnauthorizedResponse(err.Error())
	}

	// 验证成功，设置消费者信息
	setConsumerHeader(hmacParams.ConsumerName)

	// 如果需要隐藏凭证
	if cfg.HideCredentials {
		proxywasm.RemoveHttpRequestHeader(authorizationHeader)
	}

	// 如果有请求体且需要验证请求体，进入 onHttpRequestBody 方法
	if wrapper.HasRequestBody() && cfg.ValidateRequestBody {
		return types.HeaderStopIteration
	}
	ctx.DontReadRequestBody()
	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, cfg config.HmacAuthConfig, body []byte) types.Action {
	if cfg.ValidateRequestBody {
		digestHeaderVal, _ := proxywasm.GetHttpRequestHeader(digestHeader)
		if digestHeaderVal == "" {
			return sendUnauthorizedResponse("Invalid digest")
		}

		// 计算请求体的 SHA-256 摘要
		digestCreated := calculateBodyDigest(body)

		// 比较请求头中的 Digest 和服务端计算的摘要
		if digestCreated != digestHeaderVal {
			log.Warnf("Request body digest validation failed. Expected: %s, Got: %s, Body size: %d bytes",
				digestCreated, digestHeaderVal, len(body))
			return sendUnauthorizedResponse("Invalid digest")
		}
	}
	return types.ActionContinue
}

// HmacParams 存储从 Authorization 头中提取 HMAC 参数和消费者信息
type HmacParams struct {
	KeyId        string
	Algorithm    string
	Signature    string
	Headers      []string
	ConsumerName string
}

// retrieveHmacFieldsAndConsumer 从 Authorization 头中提取 HMAC 参数和消费者信息
func retrieveHmacFieldsAndConsumer(cfg config.HmacAuthConfig) (*HmacParams, error) {
	params := &HmacParams{}

	// 获取 Authorization 头
	authString, err := proxywasm.GetHttpRequestHeader(authorizationHeader)
	if err != nil {
		if err == types.ErrorStatusNotFound {
			return nil, fmt.Errorf("missing Authorization header")
		}
		return nil, err
	}

	// 检查是否以 "Signature " 开头
	if !strings.HasPrefix(authString, signaturePrefix) {
		return nil, fmt.Errorf("Authorization header does not start with 'Signature '")
	}

	// 使用正则表达式解析字段，跳过 "Signature " 前缀
	matches := fieldRegex.FindAllStringSubmatch(authString[len(signaturePrefix):], -1)

	for _, match := range matches {
		if len(match) == 3 {
			key := match[1]
			value := match[2]

			switch key {
			case "keyId":
				params.KeyId = value
			case "algorithm":
				params.Algorithm = value
			case "signature":
				params.Signature = value
			case "headers":
				// 分割 headers 字段
				if value != "" {
					params.Headers = strings.Split(value, " ")
				}
			}
		}
	}

	// 验证必要字段
	if params.KeyId == "" || params.Signature == "" {
		return nil, fmt.Errorf("keyId or signature missing")
	}

	if params.Algorithm == "" {
		return nil, fmt.Errorf("algorithm missing")
	}

	// 根据 keyId 查找消费者名称
	consumerName := ""
	found := false
	for _, consumer := range cfg.Consumers {
		if consumer.AccessKey == params.KeyId {
			consumerName = consumer.Name
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("Invalid keyId")
	}

	params.ConsumerName = consumerName
	return params, nil
}

// validateClockSkew 检查时间偏差
func validateClockSkew(clockSkew int) error {
	dateHeaderVal, _ := proxywasm.GetHttpRequestHeader(dateHeader)
	if dateHeaderVal == "" {
		return fmt.Errorf("Date header missing. failed to validate clock skew")
	}

	// 解析 GMT 格式时间
	dateTime, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", dateHeaderVal)
	if err != nil {
		return fmt.Errorf("Invalid GMT format time")
	}

	// 计算时间差
	currentTime := time.Now()
	diff := math.Abs(float64(currentTime.Unix() - dateTime.Unix()))

	// 检查是否超过 clock_skew
	if int(diff) > clockSkew {
		return fmt.Errorf("Clock skew exceeded")
	}

	return nil
}

// validateSignature 验证签名
func validateSignature(hmacParams *HmacParams, cfg config.HmacAuthConfig) error {
	// 根据 keyId 查找对应的 secretKey
	secretKey := ""
	found := false
	for _, consumer := range cfg.Consumers {
		if consumer.AccessKey == hmacParams.KeyId {
			secretKey = consumer.SecretKey
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("Invalid keyId")
	}

	// 生成 HMAC 签名
	signingString := generateSigningString(hmacParams)
	expectedSignature, err := generateHmacSignature(secretKey, hmacParams.Algorithm, signingString)
	if err != nil {
		return err
	}

	// 比较签名
	if hmacParams.Signature != expectedSignature {
		log.Warnf("Signature validation failed. Algorithm: %s, Expected: %s, Got: %s, Signing String: %s",
			hmacParams.Algorithm, expectedSignature, hmacParams.Signature, signingString)
		return fmt.Errorf("Invalid signature")
	}

	return nil
}

// generateSigningString 生成签名字符串
func generateSigningString(hmacParams *HmacParams) string {
	var signingStringItems []string
	signingStringItems = append(signingStringItems, hmacParams.KeyId)

	// 获取请求方法和路径
	requestMethod, err := proxywasm.GetHttpRequestHeader(":method")
	if err != nil {
		requestMethod = "GET"
	}

	requestURI, err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil || requestURI == "" {
		requestURI = "/"
	}

	if len(hmacParams.Headers) > 0 {
		for _, h := range hmacParams.Headers {
			if h == "@request-target" {
				requestTarget := requestMethod + " " + requestURI
				signingStringItems = append(signingStringItems, requestTarget)
			} else {
				headerValue, err := proxywasm.GetHttpRequestHeader(h)
				if err == nil {
					signingStringItems = append(signingStringItems, h+": "+headerValue)
				}
			}
		}
	}

	signingString := strings.Join(signingStringItems, "\n") + "\n"
	return signingString
}

// generateHmacSignature 生成 HMAC 签名
func generateHmacSignature(secretKey, algorithm, message string) (string, error) {
	var mac hash.Hash

	switch algorithm {
	case "hmac-sha1":
		mac = hmac.New(sha1.New, []byte(secretKey))
	case "hmac-sha256":
		mac = hmac.New(sha256.New, []byte(secretKey))
	case "hmac-sha512":
		mac = hmac.New(sha512.New, []byte(secretKey))
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	mac.Write([]byte(message))
	signature := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(signature), nil
}

// calculateBodyDigest 计算请求体的 SHA-256 摘要
func calculateBodyDigest(body []byte) string {
	hash := sha256.Sum256(body)
	encodedDigest := base64.StdEncoding.EncodeToString(hash[:])
	return "SHA-256=" + encodedDigest
}

func sendUnauthorizedResponse(message string) types.Action {
	errorResponse := fmt.Sprintf(errorResponseTemplate, message)
	proxywasm.SendHttpResponse(401, nil, []byte(errorResponse), -1)
	return types.ActionContinue
}

func setConsumerHeader(name string) {
	_ = proxywasm.AddHttpRequestHeader(consumerHeader, name)
}

func contains(arr []string, item string) bool {
	for _, i := range arr {
		if i == item {
			return true
		}
	}
	return false
}
