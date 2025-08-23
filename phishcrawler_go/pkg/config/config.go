package config

// Add these imports to your 'config' package
import (
	"fmt"
	"strconv"
)

// 🌐 URL Structure & Content
type URLFeatures struct {
	URL                  string  `json:"url"`
	URLLength            int     `json:"url_length"`
	Domain               string  `json:"domain"`
	DomainURLLength      int     `json:"domain_url_length"`
	SubdomainCount       int     `json:"subdomain_count"`
	PathSegmentCount     int     `json:"path_segment_count"`
	PathStartsWithURL    bool    `json:"path_starts_with_url"`
	HasAtSymbol          bool    `json:"has_at_symbol"`
	DashesCount          bool    `json:"dashes_count"`
	SensitiveWords       bool    `json:"sensitive_words_in_url"`
	IsIPAddress          bool    `json:"is_ip_address"`
	DigitLetterRatio     float64 `json:"digit_letter_ratio"`
	UsesHomographTrick   bool    `json:"uses_homograph_trick"`
	HasRandomLookingStr  bool    `json:"has_random_looking_str"`
	ContainsEncodedChars bool    `json:"contains_encoded_chars"`
}

// 🔒 Security & Certificate
type SecurityFeatures struct {
	IsHTTPS         bool   `json:"is_https"`
	IsCertValid     bool   `json:"is_cert_valid"`
	CertCountry     string `json:"cert_country"`
	CertReliability string `json:"cert_reliability"`
	CertIssuerOrg   string `json:"cert_issuer_organization"`
	HasSPF          bool   `json:"has_spf"`
	HasDMARC        bool   `json:"has_dmarc"`
}

// 🌎 Domain & DNS Info
type DomainFeatures struct {
	DomainAge          int    `json:"domain_age"`
	DomainCreationDate string `json:"domain_creation_date"`
	DomainEndPeriod    string `json:"domain_end_period"`
	HasDNSRecord       bool   `json:"has_dns_record"`
	HasWhois           bool   `json:"has_whois"`
}

// 📝 Page Content & Structure
type PageContentFeatures struct {
	IsValidHTML               bool `json:"is_valid_html"`
	IsErrorPage               bool `json:"is_error_page"`
	AnchorsCount              int  `json:"anchors_count"`
	FormsCount                int  `json:"forms_count"`
	JavaScriptCount           int  `json:"javascript_count"`
	ObfuscatedJavaScriptCount int  `json:"obfuscated_js_count"`
	SelfAnchorsCount          int  `json:"self_anchors_count"`
	HasFormWithURL            bool `json:"has_form_with_url"`
	HasIframe                 bool `json:"has_iframe"`
	UseMouseover              int  `json:"use_mouseover"`
}

// ✍️ Textual Analysis
type TextFeatures struct {
	MeanWordLength     int `json:"mean_word_length"`
	DistinctWordsCount int `json:"distinct_words_count"`
}

// ⚡ Behavior & Response
type BehaviorFeatures struct {
	StatusCode int `json:"status_code"`
	Redirects  int `json:"redirects"`
}

// 🏷️ Classification & Labels
type ClassificationFeatures struct {
	IsPhishing bool `json:"is_phishing"`
	Depth      int  `json:"depth"`
}

// 🔗 Reference
type Ref struct {
	URL          string `json:"url"`
	IsSameDomain bool   `json:"is_same_domain"`
	IsForm       bool   `json:"is_form"`
	IsAnchor     bool   `json:"is_anchor"`
	IsIframe     bool   `json:"is_iframe"`
	// AnchorText   string `json:"anchor_text,omitempty"`
}

// 🆕 NEW: Add a section for engineered features
type EngineeredFeatures struct {
	CertAgeDays        int     `json:"cert_age_days"`
	DomainCertAgeRatio float64 `json:"domain_cert_age_ratio"`
}

// 🌟 Final node feature wrapper
type NodeFeatures struct {
	URLFeatures
	SecurityFeatures
	DomainFeatures
	PageContentFeatures
	TextFeatures
	BehaviorFeatures
	ClassificationFeatures
	EngineeredFeatures          // Add the new struct here
	ExtractionErrors   []string `json:"extraction_errors,omitempty"` // New field for error tracking
	Refs               []Ref    `json:"refs"`
}

var EdgeCSVHeader = []string{
	"Source", "url", "is_same_domain", "is_form",
	"is_anchor", "is_iframe",
	// "anchor_text",
}

// GetCSVHeader returns the header row for the CSV file.
var NodeCSVHeader = []string{
	// URLFeatures
	"url", "url_length", "domain", "domain_url_length",
	"subdomain_count", "path_segment_count", "path_starts_with_url",
	"has_at_symbol", "dashes_count", "sensitive_words_in_url", "is_ip_address",
	"digit_letter_ratio", "uses_homograph_trick", "has_random_looking_str",
	"contains_encoded_chars",

	// SecurityFeatures
	"is_https", "is_cert_valid", "cert_country", "cert_reliability",
	"cert_issuer_organization", "has_spf", "has_dmarc",

	// DomainFeatures
	"domain_age", "domain_creation_date", "domain_end_period", "has_dns_record",
	"has_whois",

	// PageContentFeatures
	"is_valid_html", "is_error_page", "anchors_count", "forms_count", "javascript_count",
	"obfuscated_js_count", "self_anchors_count", "has_form_with_url", "has_iframe",
	"use_mouseover",

	// TextFeatures
	"mean_word_length", "distinct_words_count",

	// BehaviorFeatures
	"status_code", "redirects",

	// ClassificationFeatures
	"is_phishing", "depth",

	// Refs (flattened for CSV)
	"refs_count", "refs_same_domain_count",

	// Engineered Features
	"cert_age_days", "domain_cert_age_ratio",
	// // New Error Column
	// "extraction_errors",
}

// unexported helper to convert boolean to "1" or "0"
func btoi(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// *** NEW: ToEdgeCSVRow method creates a formatted slice for the edge CSV ***
func (r *Ref) ToEdgeCSVRow(sourceURL string) []string {
	// var anchorText string
	// if r.AnchorText != "" {
	// 	anchorText = r.AnchorText
	// } else {
	// 	anchorText = ""
	// }
	return []string{
		sourceURL,
		r.URL,
		btoi(r.IsSameDomain),
		btoi(r.IsForm),
		btoi(r.IsAnchor),
		btoi(r.IsIframe),
		// anchorText,
	}
}

// GetCSVHeader returns the header row for the CSV file.
func (nf NodeFeatures) GetCSVHeader() []string {
	return NodeCSVHeader
}

// Helper to convert boolean to 1 or 0
// btoi := func(b bool) string {
// 	if b {
// 		return "True"
// 	}
// 	return "False"
// }

// ToCSVRow converts the NodeFeatures struct into a slice of strings for CSV output.
func (nf NodeFeatures) ToCSVRow() []string {
	// Calculate flattened ref counts
	refsCount := len(nf.Refs)
	refsSameDomainCount := 0
	for _, ref := range nf.Refs {
		if ref.IsSameDomain {
			refsSameDomainCount++
		}
	}

	row := make([]string, len(NodeCSVHeader))
	for i, header := range NodeCSVHeader {
		switch header {
		// --- URLFeatures ---
		case "url":
			if nf.URL == "" {
				row[i] = ""
			} else {
				row[i] = nf.URL
			}
		case "url_length":
			if nf.URLLength == 0 {
				row[i] = ""
			} else {
				row[i] = strconv.Itoa(nf.URLLength)
			}
		case "domain":
			if nf.Domain == "" {
				row[i] = ""
			} else {
				row[i] = nf.Domain
			}
		case "domain_url_length":
			if nf.DomainURLLength == 0 {
				row[i] = ""
			} else {
				row[i] = strconv.Itoa(nf.DomainURLLength)
			}
		case "subdomain_count":
			row[i] = strconv.Itoa(nf.SubdomainCount) // 0 is a valid count
		case "path_segment_count":
			if nf.PathSegmentCount == 0 {
				row[i] = ""
			} else {
				row[i] = strconv.Itoa(nf.PathSegmentCount)
			}
		case "digit_letter_ratio":
			row[i] = fmt.Sprintf("%.4f", nf.DigitLetterRatio) // 0.0000 is a valid ratio

		// --- SecurityFeatures ---
		case "cert_country":
			if nf.CertCountry == "" {
				row[i] = ""
			} else {
				row[i] = nf.CertCountry
			}
		case "cert_reliability":
			if nf.CertReliability == "" {
				row[i] = ""
			} else {
				row[i] = nf.CertReliability
			}
		case "cert_issuer_organization":
			if nf.CertIssuerOrg == "" {
				row[i] = ""
			} else {
				row[i] = nf.CertIssuerOrg
			}

		// --- DomainFeatures ---
		case "domain_age":
			if nf.DomainAge == 0 && !nf.HasWhois { // Only -1 if WHOIS failed
				row[i] = ""
			} else {
				row[i] = strconv.Itoa(nf.DomainAge)
			}
		case "domain_creation_date":
			if nf.DomainCreationDate == "" {
				row[i] = ""
			} else {
				row[i] = nf.DomainCreationDate
			}
		case "domain_end_period":
			if nf.DomainEndPeriod == "" {
				row[i] = ""
			} else {
				row[i] = nf.DomainEndPeriod
			}

		// --- PageContentFeatures ---
		case "anchors_count":
			row[i] = strconv.Itoa(nf.AnchorsCount)
		case "forms_count":
			row[i] = strconv.Itoa(nf.FormsCount)
		case "javascript_count":
			row[i] = strconv.Itoa(nf.JavaScriptCount)
		case "obfuscated_js_count":
			row[i] = strconv.Itoa(nf.ObfuscatedJavaScriptCount)
		case "self_anchors_count":
			row[i] = strconv.Itoa(nf.SelfAnchorsCount)
		case "use_mouseover":
			row[i] = strconv.Itoa(nf.UseMouseover)

		// --- TextFeatures ---
		case "mean_word_length":
			if nf.MeanWordLength == 0 {
				row[i] = ""
			} else {
				row[i] = strconv.Itoa(nf.MeanWordLength)
			}
		case "distinct_words_count":
			if nf.DistinctWordsCount == 0 {
				row[i] = ""
			} else {
				row[i] = strconv.Itoa(nf.DistinctWordsCount)
			}

		// --- BehaviorFeatures ---
		case "status_code":
			if nf.StatusCode == 0 {
				row[i] = ""
			} else {
				row[i] = strconv.Itoa(nf.StatusCode)
			}
		case "redirects":
			row[i] = strconv.Itoa(nf.Redirects) // 0 is a valid count

		// --- ClassificationFeatures ---
		case "depth":
			row[i] = strconv.Itoa(nf.Depth)

			// --- EngineeredFeatures ---
		case "cert_age_days":
			row[i] = strconv.Itoa(nf.CertAgeDays)
		case "domain_cert_age_ratio":
			row[i] = fmt.Sprintf("%.4f", nf.DomainCertAgeRatio)

		// --- Refs ---
		case "refs_count":
			row[i] = strconv.Itoa(refsCount)
		case "refs_same_domain_count":
			row[i] = strconv.Itoa(refsSameDomainCount)

		// // --- Error Column ---
		// case "extraction_errors":
		// 	if len(nf.ExtractionErrors) == 0 {
		// 		row[i] = ""
		// 	} else {
		// 		row[i] = strings.Join(nf.ExtractionErrors, "; ")
		// 	}

		// --- Boolean fields (no change) ---
		// NOTE: Boolean fields are left as True/False because 'False' is meaningful data,
		// not an indicator of missing information.
		case "path_starts_with_url":
			row[i] = btoi(nf.PathStartsWithURL)
		case "has_at_symbol":
			row[i] = btoi(nf.HasAtSymbol)
		case "dashes_count":
			row[i] = btoi(nf.DashesCount)
		case "sensitive_words_in_url":
			row[i] = btoi(nf.SensitiveWords)
		case "is_ip_address":
			row[i] = btoi(nf.IsIPAddress)
		case "uses_homograph_trick":
			row[i] = btoi(nf.UsesHomographTrick)
		case "has_random_looking_str":
			row[i] = btoi(nf.HasRandomLookingStr)
		case "contains_encoded_chars":
			row[i] = btoi(nf.ContainsEncodedChars)
		case "is_https":
			row[i] = btoi(nf.IsHTTPS)
		case "is_cert_valid":
			row[i] = btoi(nf.IsCertValid)
		case "has_spf":
			row[i] = btoi(nf.HasSPF)
		case "has_dmarc":
			row[i] = btoi(nf.HasDMARC)
		case "has_dns_record":
			row[i] = btoi(nf.HasDNSRecord)
		case "has_whois":
			row[i] = btoi(nf.HasWhois)
		case "is_valid_html":
			row[i] = btoi(nf.IsValidHTML)
		case "is_error_page":
			row[i] = btoi(nf.IsErrorPage)
		case "has_form_with_url":
			row[i] = btoi(nf.HasFormWithURL)
		case "has_iframe":
			row[i] = btoi(nf.HasIframe)
		case "is_phishing":
			row[i] = btoi(nf.IsPhishing)

		default:
			row[i] = "" // Should not happen if csvHeaderOrder is complete
		}
	}
	return row
}
