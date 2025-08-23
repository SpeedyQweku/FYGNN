package common

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Get the Certificate Reliability
func GetCertReliability(cert *x509.Certificate, issuerO string) int {
	trustedIssuers := []string{
		"Actalis", "Amazon", "Apple", "Buypass", "Certigna", "Certum", "CFCA",
		"Chunghwa Telecom", "Comodo", "Cybertrust", "DigiCert", "Doster", "Entrust",
		"eMudhra", "Firmaprofesional", "GeoTrust", "GlobalSign", "GoDaddy", "IdenTrust",
		"Internet2", "Let's Encrypt", "Microsoft", "NetLock", "Network Solutions",
		"QuoVadis", "Secom", "SSL.com", "StartCom", "SwissSign", "Symantec",
		"Telia Company", "Thawte", "TrustCor", "Trustwave", "TWCA", "Unizeto", "VeriSign",
		"Verizon", "Wells Fargo", "WISeKey", "WoSign", "Xolphin", "Google Trust Services",
	}

	isTrusted := false
	for _, prefix := range trustedIssuers {
		if strings.HasPrefix(issuerO, prefix) {
			isTrusted = true
			break
		}
	}

	trustedScore := 0
	if isTrusted {
		trustedScore = 1
	}
	// fmt.Println(cert.Verify())

	duration := cert.NotAfter.Sub(cert.NotBefore)
	durationScore := 0
	if duration.Hours()/24 > 365 {
		durationScore = 1
	}

	return trustedScore + durationScore // total: 0, 1, or 2
}

// Reliability Score System
func MapReliabilityScore(score int) string {
	switch score {
	case 2:
		return "HIGH"
	case 1:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Help to format the Date and Time
func RegexpDateTime(raw string) (time.Time, string) {
	re := regexp.MustCompile(`^(\d{8})`)
	match := re.FindStringSubmatch(raw)
	if len(match) > 1 {
		date, err := time.Parse("20060102", match[1])
		if err == nil {
			return date, ""
		}
	}
	return time.Time{}, raw
}

// Get the Issuer Organization of a Certificate
func GetIssuerOrganization(cert *x509.Certificate) string {
	for _, name := range cert.Issuer.Names {
		if name.Type.String() == "2.5.4.10" { // Organization
			return fmt.Sprintf("%v", name.Value)
		}
	}
	return ""
}

// Help to find sensitive words
func HasSensitiveWords(url string) bool {
	sensitiveWordsList := []string{
		"login", "secure", "account", "ebay", "paypal", "update", "verify",
		"bank", "signin", "submit", "security", "billing", "password",
		"webscr", "support", "confirm", "connect", "authorize", "checkout",
		"payment", "alert", "notification", "limited", "urgent", "important",
		"invoice", "access", "client", "identity", "recover", "reset",
		"amazon", "apple", "microsoft", "google", "facebook", "dropbox",
		"office365", "outlook", "icloud", "admin", "service", "verify-now",
		"login-secure", "account-update", "free", "bonus", "cash", "winner",
		"promo", "offer", "deal", "gift", "earn", "income", "crypto",
		"btc", "eth", "wallet", "investment", "trading", "exchange", "get-rich",
		"validate", "unlock", "suspended", "dns", "whois", "server",
	}

	urlLower := strings.ToLower(url)
	for _, word := range sensitiveWordsList {
		if strings.Contains(urlLower, word) {
			return true
		}
	}
	return false
}

// Calculating digits to letters ratio
func CalDigitLetterRatio(domain string) float64 {
	digits := 0
	letters := 0
	for _, ch := range domain {
		if ch >= '0' && ch <= '9' {
			digits++
		} else if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			letters++
		}
	}
	if letters == 0 {
		if digits > 0 {
			return float64(digits) // all digits, no letters
		}
		return 0
	}
	return float64(digits) / float64(letters)
}

// Check JS is obfuscated
func LooksLikeObfuscatedJS(js string) bool {
	js = strings.ToLower(js)

	// Check for common obfuscation patterns
	if strings.Contains(js, "eval(") ||
		strings.Contains(js, "unescape(") ||
		strings.Contains(js, "String.fromCharCode") ||
		len(js) > 1000 || // very large inline script
		hasLongUnbrokenString(js) {
		return true
	}
	return false
}

func hasLongUnbrokenString(js string) bool {
	// Check for very long word with no spaces (e.g. base64 or packed)
	words := strings.Fields(js)
	for _, w := range words {
		if len(w) > 50 {
			return true
		}
	}
	return false
}

// Check for random string patterns: many digits + consonants, no vowels, etc
func HasRandomLookingString(domain string) bool {
	// Example: domains with low vowel ratio, long consonant runs
	vowelCount := 0
	for _, ch := range domain {
		if strings.ContainsRune("aeiou", unicode.ToLower(ch)) {
			vowelCount++
		}
	}
	vowelRatio := float64(vowelCount) / float64(len(domain))
	return vowelRatio < 0.2
}

// Detect basic homograph tricks (e.g. using 0 for o, 1 for l, accented chars)
func UsesHomographTrick(domain string) (bool, error) {
	decoded, err := idna.ToUnicode(domain)
	if err != nil {
		// Return the error instead of printing it
		return false, fmt.Errorf("punycode decode error: %w", err)
	}

	hasLatin := false
	hasOther := false

	for _, r := range decoded {
		switch {
		case unicode.In(r, unicode.Latin):
			hasLatin = true
		default:
			if unicode.IsLetter(r) {
				hasOther = true
			}
		}
	}

	if hasLatin && hasOther {
		return true, nil
	}
	return false, nil
}

func SubdomainCount(domain string) int {
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return strings.Count(domain, ".")
	} else {
		if len(domain) > len(eTLDPlusOne) {
			// Trim the eTLD+1 and the dot, then count remaining dots
			subdomainPart := domain[:len(domain)-len(eTLDPlusOne)-1]
			return strings.Count(subdomainPart, ".") + 1
		} else {
			return 0
		}
	}
}

// NormalizeURL ensures a URL has a scheme.
func NormalizeURL(rawURL string) string {
	if rawURL != "" && !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "https://" + rawURL
	}
	return rawURL
}

// parseWhoisDate tries multiple common layouts to parse a date string.
func ParseWhoisDate(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}

	// First, try to find a YYYYMMDD format anywhere in the string.
	re := regexp.MustCompile(`(\d{8})`)
	match := re.FindStringSubmatch(raw)
	if len(match) > 1 {
		t, err := time.Parse("20060102", match[1])
		if err == nil {
			return t, true
		}
	}

	// If that fails, fall back to trying a list of common layouts.
	layouts := []string{
		// Common ISO and database formats
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",

		// Common US and European formats with different delimiters
		"02-Jan-2006",
		"2006/01/02",
		"2006.01.02",
		"02.01.2006",

		// Formats with time and timezone info
		"2006-01-02 15:04:05 MST",
		"Mon, 02 Jan 2006 15:04:05 MST", // RFC1123Z
	}

	for _, layout := range layouts {
		t, err := time.Parse(layout, raw)
		if err == nil {
			return t, true
		}
	}

	// If all methods fail
	return time.Time{}, false
}

// CanonicalizeURL standardizes a URL for consistent graph node representation.
func CanonicalizeURL(u *url.URL) string {
	// Convert scheme and host to lowercase
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	// Remove the fragment
	u.Fragment = ""
	return u.String()
}
