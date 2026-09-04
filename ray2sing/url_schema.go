package ray2sing

import (
	"net/url"
	"regexp"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// HysteriaURLData holds the parsed data from a Hysteria URL.
type UrlSchema struct {
	Scheme   string
	Username string
	Password string
	Hostname string
	Port     uint16
	Name     string
	Params   map[string]string
}

func (u UrlSchema) GetServerOption() T.ServerOptions {
	return T.ServerOptions{
		Server:     u.Hostname,
		ServerPort: u.Port,
	}
}

// func (u UrlSchema) GetRelayOptions() (*T.TurnRelayOptions, error) {
// 	return ParseTurnURL(u.Params["relay"])
// }

// parseHysteria2 parses a given URL and returns a HysteriaURLData struct.
func ParseUrl(inputURL string, defaultPort uint16) (*UrlSchema, error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return nil, err
	}
	port := toUInt16(parsedURL.Port(), defaultPort)

	data := &UrlSchema{
		Scheme:   parsedURL.Scheme,
		Username: parsedURL.User.Username(),
		Password: getPassword(parsedURL),
		Hostname: parsedURL.Hostname(),
		Port:     port,
		Name:     parsedURL.Fragment,
		Params:   make(map[string]string),
	}
	if isBase64CharsOnly(data.Username) {
		userInfo, err := decodeBase64IfNeeded(data.Username)

		// fmt.Print(userInfo)
		if err == nil && isValidChar(userInfo) {
			// If decoding is successful, use the decoded string
			userDetails := strings.Split(userInfo, ":")
			if len(userDetails) == 2 {
				data.Username = userDetails[0]
				data.Password = userDetails[1]
			}
		}
	}

	for key, values := range parsedURL.Query() {
		data.Params[canonicalParamKey(key)] = strings.Join(values, ",")
	}

	return data, nil
}

// canonicalParamKey is the single normalization contract every protocol
// parser's parameter lookups must agree with. A link author may spell a
// query key with hyphens, underscores, spaces, or mixed case
// (obfs-password, obfs_password, obfsPassword, OBFS-PASSWORD); all of these
// must resolve to the same stored key. Earlier revisions replaced '_'/'-'
// with a literal space, which does not round-trip through a plain map
// index (decoded["obfs-password"] never matches a key stored as
// "obfs password") and gave every protocol file its own ad-hoc,
// undocumented assumption about the result. Stripping separators instead
// of substituting them removes that ambiguity: "obfs-password",
// "obfs_password" and "obfsPassword" all canonicalize to "obfspassword",
// matching the no-separator alias spellings most parsers already use.
//
// ParseUrl runs every query key through this before storing it in
// UrlSchema.Params. Any code reading UrlSchema.Params must do the same
// canonicalization on the key it looks up - use getParam/getOneOf/getOneOfN
// rather than indexing Params directly with a literal that assumes a
// particular separator style.
func canonicalParamKey(ss string) string {
	s := strings.ToLower(strings.TrimSpace(ss))
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '_', '-', ' ', '\t':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// normalizeStr is kept as the historical name for canonicalParamKey: it is
// still the function ParseUrl and getOneOfN both call, so every caller of
// either keeps normalizing keys through exactly one place.
func normalizeStr(ss string) string {
	return canonicalParamKey(ss)
}

func getPassword(u *url.URL) string {
	if password, ok := u.User.Password(); ok {
		return password
	}
	return ""
}

var base64CharRegex = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

func isBase64CharsOnly(s string) bool {
	return base64CharRegex.MatchString(s)
}

var validCharRegex = regexp.MustCompile(`^[A-Za-z0-9+/=_)(: !~@#$%^&*-]+$`)

func isValidChar(s string) bool {

	return validCharRegex.MatchString(s)
}
