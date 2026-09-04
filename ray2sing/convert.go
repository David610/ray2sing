package ray2sing

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"strconv"
	"strings"

	_ "github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var configTypes = map[string]ParserFunc{
	"vmess://":     VmessSingbox,
	"vless://":     VlessSingbox,
	"trojan://":    TrojanSingbox,
	"svmess://":    VmessSingbox,
	"svless://":    VlessSingbox,
	"strojan://":   TrojanSingbox,
	"ss://":        ShadowsocksSingbox,
	"tuic://":      TuicSingbox,
	"hysteria://":  HysteriaSingbox,
	"hysteria2://": Hysteria2Singbox,
	"hy2://":       Hysteria2Singbox,
	"ssh://":       SSHSingbox,
	"naive://":     NaiveSingbox,

	"ssconf://":  BeepassSingbox,
	"direct://":  DirectSingbox,
	"socks://":   SocksSingbox,
	"phttp://":   HttpSingbox,
	"phttps://":  HttpsSingbox,
	"http://":    HttpSingbox,
	"https://":   HttpsSingbox,
	"xvmess://":  VmessXray,
	"xvless://":  VlessXray,
	"xtrojan://": TrojanXray,
	"xdirect://": DirectXray,
	"mieru://":   MieruSingbox,
	"mierus://":  MieruSingbox,
	"psiphon://": PsiphonSingbox,
	"dnstt://":   DnsttSingbox,
}
var endpointParsers = map[string]EndpointParserFunc{
	"wg://":        AWGSingbox,
	"wireguard://": AWGSingbox,
	"warp://":      WarpSingbox,
	"awg://":       AWGSingbox,
	"[Interface]":  AWGSingboxTxt,
}

func decodeUrlBase64IfNeeded(config string) string {
	splt := strings.SplitN(config, "://", 2)
	if len(splt) < 2 {
		//return config
	}
	rest, _ := decodeBase64IfNeeded(splt[1])
	// fmt.Println(rest, err)
	return splt[0] + "://" + rest
}

type OutEnd struct {
	outbound *T.Outbound
	endpoint *T.Endpoint
}

// matchSchemeCaseInsensitive finds the parser registered for config's
// scheme, matching the scheme portion (before "://") case-insensitively -
// URI schemes are case-insensitive per RFC 3986, and Tamara's Flutter
// classifier already accepts VLESS://, Vless://, vless:// interchangeably,
// so Core dispatch must agree. Only the scheme is compared/replaced;
// credentials, host, path and query are returned untouched. Non-URI table
// entries (e.g. the WireGuard "[Interface]" text marker) have no "://" and
// are matched case-sensitively, unaffected by this.
func matchSchemeCaseInsensitive[V any](config string, table map[string]V) (rewritten string, parser V, ok bool) {
	schemeEnd := strings.Index(config, "://")
	if schemeEnd < 0 {
		parser, ok = table[config]
		return config, parser, ok
	}
	lowerScheme := strings.ToLower(config[:schemeEnd])
	for k, v := range table {
		keySchemeEnd := strings.Index(k, "://")
		if keySchemeEnd < 0 || keySchemeEnd != schemeEnd {
			continue
		}
		if strings.ToLower(k[:keySchemeEnd]) != lowerScheme {
			continue
		}
		// k already ends in "://" (it's a configTypes/endpointParsers key);
		// config[schemeEnd:] still starts with "://" too, so skip past it
		// here or the reconstructed URL would read "scheme://://rest".
		return k + config[schemeEnd+len("://"):], v, true
	}
	return config, parser, false
}

func processSingleConfig(config string, useXrayWhenPossible bool) (outend *OutEnd, err error) {
	defer func() {
		if r := recover(); r != nil {
			outend = nil
			stackTrace := make([]byte, 1024)
			s := runtime.Stack(stackTrace, false)
			stackStr := fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing:", r, "Stack trace:", stackStr)
		}
	}()
	// configDecoded := decodeUrlBase64IfNeeded(config)
	outend = &OutEnd{}
	// useXrayWhenPossible ("use Xray core when possible") and the
	// "&core=xray" link hint are accepted for backward compatibility with
	// stored settings/links but are currently inert: there is no automatic
	// preference of an Xray-backed parser for an ordinary vless://,
	// vmess://, trojan:// or direct:// link. The Xray-backed parsers
	// themselves are not dead code - they remain directly reachable via the
	// explicit xvless://, xvmess://, xtrojan:// and xdirect:// schemes in
	// configTypes above - only the "prefer Xray automatically" behavior
	// this flag used to gate is unimplemented. Tamara's settings UI no
	// longer exposes a toggle claiming this flag changes parsing behavior.
	_ = useXrayWhenPossible
	if outend.outbound == nil {
		if rewritten, v, ok := matchSchemeCaseInsensitive(config, configTypes); ok {
			outend.outbound, err = v(rewritten)
		}
		if outend.outbound == nil && err == nil {
			if rewritten, v, ok := matchSchemeCaseInsensitive(config, endpointParsers); ok {
				outend.endpoint, err = v(rewritten)
			}
		}
	}

	if err != nil {
		return nil, err
	}
	if outend.endpoint == nil && outend.outbound == nil {
		return nil, E.New("Not supported config type")
	}
	if outend.outbound != nil && outend.outbound.Tag == "" {
		outend.outbound.Tag = outend.outbound.Type
	}
	if outend.endpoint != nil && outend.endpoint.Tag == "" {
		outend.endpoint.Tag = outend.endpoint.Type
	}

	// json.MarshalIndent(configSingbox, "", "  ")
	return outend, nil
}

// ParseWarning records one subscription/multi-link entry that failed to
// parse, keyed by its position among the *candidate* (non-blank,
// non-comment) entries GenerateConfigLiteWithWarnings actually attempted -
// so a caller can report "entry 3 of 14 failed: ..." without ever needing
// the raw entry text (which may carry credentials). Snippet is a short,
// non-secret prefix suitable for a diagnostic (see redactSnippet).
type ParseWarning struct {
	Index   int
	Snippet string
	Err     error
}

func (w ParseWarning) Error() string {
	return fmt.Sprintf("entry %d (%s): %v", w.Index, w.Snippet, w.Err)
}

// redactSnippet returns a short, secret-safe prefix of a candidate entry
// for diagnostics: the scheme (if any) plus a length, never credentials,
// host, or query content.
func redactSnippet(config string) string {
	scheme := "unknown"
	if idx := strings.Index(config, "://"); idx > 0 && idx < 32 {
		scheme = strings.ToLower(config[:idx])
	} else if len(config) > 0 && (config[0] == '{' || config[0] == '[') {
		scheme = "json"
	}
	return fmt.Sprintf("scheme=%s len=%d", scheme, len(config))
}

// GenerateConfigLite keeps its historical signature/behavior (partial
// success, warnings discarded) for any existing caller that only wants
// *option.Options. Use GenerateConfigLiteWithWarnings to learn about
// entries that failed to parse instead of only seeing them printed to
// stderr - see that function's doc comment for the fail-open/fail-closed
// policy this implements.
func GenerateConfigLite(input string, useXrayWhenPossible bool) (*option.Options, error) {
	options, _, err := GenerateConfigLiteWithWarnings(input, useXrayWhenPossible)
	return options, err
}

// GenerateConfigLiteWithWarnings implements Tamara's fail-open-with-visible-
// warnings policy for multi-entry input (a subscription body, a multi-line
// paste): blank lines and comment lines are silently skipped (never
// warned about), but any candidate entry that looks like a proxy
// config/link and fails to parse is recorded as a ParseWarning instead of
// only being printed to stderr and forgotten. The call still succeeds
// (non-nil *option.Options, nil error) as long as at least one entry
// parsed, so one broken server in a large subscription does not reject the
// whole subscription - but the caller now always has the means to learn
// which entries were dropped and show that to the user, instead of a
// silent partial import. A single-entry input that fails still returns a
// nil *option.Options and a non-nil error exactly as before: there is
// nothing "partial" about importing one link.
func GenerateConfigLiteWithWarnings(input string, useXrayWhenPossible bool) (*option.Options, []ParseWarning, error) {

	configArray := expandDecodedConfig(input)

	var outbounds []T.Outbound
	var endpoints []T.Endpoint
	var warnings []ParseWarning
	counter := 0

	for _, config := range configArray {
		if len(config) < 5 || config[0] == '#' || config[0] == '/' {
			continue
		}
		detourTag := ""

		chains := strings.Split(config, " -> ")
		for i := len(chains) - 1; i >= 0; i-- {
			chain1 := chains[i]

			// fmt.Printf("%s", chain)
			chain, _ := decodeBase64IfNeeded(chain1)
			outend, err := processSingleConfig(chain, useXrayWhenPossible)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Error in entry %d: %v\n", counter, err)
				warnings = append(warnings, ParseWarning{
					Index:   counter,
					Snippet: redactSnippet(chain),
					Err:     err,
				})
				counter += 1
				continue
			}

			if outend.outbound != nil {
				outend.outbound.Tag += " § " + strconv.Itoa(counter)
				if dialerOpt, ok := outend.outbound.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					d.Detour = detourTag
					dialerOpt.ReplaceDialerOptions(d)
				}

				detourTag = outend.outbound.Tag
				outbounds = append(outbounds, *outend.outbound)

			} else if outend.endpoint != nil {
				outend.endpoint.Tag += " § " + strconv.Itoa(counter)
				if dialerOpt, ok := outend.endpoint.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					d.Detour = detourTag
					dialerOpt.ReplaceDialerOptions(d)
				}

				detourTag = outend.endpoint.Tag
				endpoints = append(endpoints, *outend.endpoint)

			}

			counter += 1

		}

	}

	if len(outbounds) == 0 && len(endpoints) == 0 {
		if len(warnings) > 0 {
			return nil, warnings, E.New(fmt.Sprintf("No outbounds found: all %d candidate entries failed to parse; first error: %v", len(warnings), warnings[0].Err))
		}
		return nil, warnings, E.New("No outbounds found")
	}

	fullConfig := T.Options{
		Outbounds: outbounds,
		Endpoints: endpoints,
	}

	return &fullConfig, warnings, nil
}

// Ray2SingboxOptionsWithWarnings is Ray2SingboxOptions plus the same
// per-entry ParseWarning list GenerateConfigLiteWithWarnings returns - see
// its doc comment for the fail-open-with-visible-warnings policy.
func Ray2SingboxOptionsWithWarnings(ctx context.Context, configs string, useXrayWhenPossible bool) (out *option.Options, warnings []ParseWarning, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			stackTrace := make([]byte, 1024)
			s := runtime.Stack(stackTrace, false)
			stackStr := fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing", "Stack trace:", stackStr)
		}
	}()

	configs, _ = decodeBase64IfNeeded(configs)

	return GenerateConfigLiteWithWarnings(configs, useXrayWhenPossible)
}

func Ray2Singbox(ctx context.Context, configs string, useXrayWhenPossible bool) (out []byte, err error) {
	convertedData, err := Ray2SingboxOptions(ctx, configs, useXrayWhenPossible)
	// err = libbox.CheckConfigOptions(convertedData)
	// if err != nil {
	// 	return nil, err
	// }
	return convertedData.MarshalJSONContext(ctx)
}

// Ray2SingboxOptions keeps its historical signature (warnings discarded) for
// existing callers; see Ray2SingboxOptionsWithWarnings. Its panic-recovery
// path used to embed the raw input (which may contain proxy credentials) in
// the returned error - delegating to the shared implementation instead of
// duplicating the recover() removes that secret-leaking error path.
func Ray2SingboxOptions(ctx context.Context, configs string, useXrayWhenPossible bool) (out *option.Options, err error) {
	out, _, err = Ray2SingboxOptionsWithWarnings(ctx, configs, useXrayWhenPossible)
	return out, err
}
