package cmd

import (
	"context"
	"crypto/tls"
	"net/http"
	neturl "net/url"
	"phishcrawler/pkg/config"
	"sync"
	"time"

	"github.com/likexian/whois"
)

// Crawler holds the state and dependencies for the crawling process.
type Crawler struct {
	httpClient  *http.Client
	whoisClient *whois.Client
	visited     *visitedMap
}

// visitedMap is a thread-safe map to track visited URLs.
type visitedMap struct {
	m  map[string]bool
	mu sync.Mutex
}

// checkAndAdd atomically checks if a URL has been visited and adds it if not.
func (v *visitedMap) checkAndAdd(url string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.m[url] {
		return false // Already visited
	}
	v.m[url] = true
	return true
}

func (c *Crawler) CheckAndAdd(url string) bool {
	return c.visited.checkAndAdd(url)
}

// And a simple visited checker for the initial seeding
func (c *Crawler) Visited(url string) bool {
	// New changes
	c.visited.mu.Lock()
	defer c.visited.mu.Unlock()
	_, exists := c.visited.m[url]
	return exists
}

// NewCrawler creates and initializes a new Crawler instance.
func NewCrawler() (*Crawler, error) {
	// Create a single, powerful, reusable HTTP client.
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second, 
	}

	return &Crawler{
		httpClient:  httpClient,
		whoisClient: whois.NewClient(),
		visited: &visitedMap{
			m: make(map[string]bool),
		},
	}, nil
}


// ExtractFeatures is the main entry point, now accepting a context.
func (c *Crawler) ExtractFeatures(ctx context.Context, rawURL string, depth int, label *bool) (*config.NodeFeatures, error) {
	features := &config.NodeFeatures{}
	features.Depth = depth

	// Set the URL to the original rawURL as a fallback in case crawling fails.
	features.URL = rawURL

	initialURL, err := neturl.Parse(rawURL)
	if err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "initial_url_parse_failed:"+err.Error())
		// Analyze the invalid URL to populate what we can and return.
		analyzeURL("", rawURL, "", features)
		return features, err
	}

	// 1. Crawl the page. This is the MOST important first step.
	// It will follow redirects and update features.URL to the final destination.
	if err := c.crawlAndExtractPageContent(ctx, initialURL, features); err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "page_content_failed:"+err.Error())
	}

	// 2. Now that features.URL holds the definitive final URL, parse it.
	finalURL, err := neturl.Parse(features.URL)
	if err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "final_url_parse_failed:"+err.Error())
		// Analyze the broken final URL and return, as we cannot proceed.
		analyzeURL("", features.URL, "", features)
		return features, err
	}

	// 3. With the final URL and its parts, now run the complete URL analysis.
	// This ensures all URL-based features (Domain, URLLength, PathSegmentCount, etc.)
	// are consistent with the final destination.
	domain := finalURL.Hostname()
	path := finalURL.Path
	analyzeURL(domain, features.URL, path, features)

	// 4. Proceed with all other lookups (DNS, WHOIS, Cert) using the final, correct domain.
	if err := c.lookupDNS(ctx, domain, features); err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "dns_lookup_failed:"+err.Error())
	}

	if err := c.extractWhois(ctx, domain, features); err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "whois_extraction_failed:"+err.Error())
	}

	if err := c.extractCertificate(ctx, domain, features); err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "cert_extraction_failed:"+err.Error())
	}

	// 5. Calculate the engineered feature ratio
	if features.CertAgeDays > 0 && features.DomainAge > 0 {
		// Convert domain age from years to days for an accurate ratio
		domainAgeInDays := features.DomainAge * 365
		if features.CertAgeDays > 0 { // Avoid division by zero
			features.DomainCertAgeRatio = float64(domainAgeInDays) / float64(features.CertAgeDays)
		}
	}

	// If a ground-truth label was provided, use it.
	if label != nil {
		features.IsPhishing = (*label == true)
	}

	return features, nil
}




/* // ExtractFeatures is the main entry point, now accepting a context.
func (c *Crawler) ExtractFeatures(ctx context.Context, rawURL string, depth int, label *bool) (*config.NodeFeatures, error) {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	features := &config.NodeFeatures{}
	features.Depth = depth

	domain := u.Hostname()
	path := u.Path

	analyzeURL(domain, rawURL, path, features)

	// 1. Crawl and get page content.
	if err := c.crawlAndExtractPageContent(ctx, u, features); err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "page_content_failed:"+err.Error())
	}

	finalURL, err := neturl.Parse(features.URL)
	// _, err = neturl.Parse(features.URL)
	if err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "final_url_parse_failed:"+err.Error())
	} else {
		domain = finalURL.Hostname()
	}

	// 2. DNS Lookup
	if err := c.lookupDNS(ctx, domain, features); err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "dns_lookup_failed:"+err.Error())
	}

	// 3. Whois Lookup
	if err := c.extractWhois(ctx, domain, features); err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "whois_extraction_failed:"+err.Error())
	}

	// 4. Certificate Info
	if err := c.extractCertificate(ctx, domain, features); err != nil {
		features.ExtractionErrors = append(features.ExtractionErrors, "cert_extraction_failed:"+err.Error())
	}

	// 5. 🆕 Calculate the engineered feature ratio
	if features.CertAgeDays > 0 {
		// Convert domain age from years to days for an accurate ratio
		domainAgeInDays := features.DomainAge * 365
		features.DomainCertAgeRatio = float64(domainAgeInDays) / float64(features.CertAgeDays)
	}

	// If a ground-truth label was provided, use it.
	if label != nil {
		features.IsPhishing = (*label == true)
		// } else {
		// 	// Otherwise, fall back to the old heuristic for discovered URLs.
		// 	if features.HasFormWithURL || features.HasIframe || features.UseMouseover > 0 ||
		// 		features.Redirects > 2 || features.JavaScriptCount > 5 || features.ObfuscatedJavaScriptCount > 0 {
		// 		features.IsPhishing = true
		// 	}
	}

	return features, nil
}
 */