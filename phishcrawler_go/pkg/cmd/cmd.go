package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"io"
	"path/filepath"

	"net"
	"net/http"
	neturl "net/url"
	"os"
	"phishcrawler/pkg/common"
	"phishcrawler/pkg/config"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/miekg/dns"
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// phishtankURL holds a URL and its ground-truth label.
type phishtankURL struct {
	URL   string
	Label bool
}

// Analyze URL for Info(IsIP,Has@,...)
func analyzeURL(domain, url, path string, nf *config.NodeFeatures) {
	pathLower := strings.ToLower(path)
	nf.URLLength = len(url)
	nf.URL = url
	nf.IsIPAddress = net.ParseIP(domain) != nil
	nf.DomainURLLength = len(domain)
	nf.HasAtSymbol = strings.Contains(url, "@")
	nf.DashesCount = strings.Contains(url, "-")
	nf.Domain = domain
	nf.HasRandomLookingStr = common.HasRandomLookingString(domain)
	nf.UsesHomographTrick, _ = common.UsesHomographTrick(domain)
	nf.SubdomainCount = common.SubdomainCount(domain)
	nf.PathSegmentCount = len(strings.Split(strings.Trim(path, "/"), "/"))
	nf.SensitiveWords = common.HasSensitiveWords(url)
	nf.DigitLetterRatio = common.CalDigitLetterRatio(domain)
	nf.PathStartsWithURL = strings.HasPrefix(pathLower, "http://") ||
		strings.HasPrefix(pathLower, "https://") ||
		strings.Contains(pathLower, "http") ||
		strings.Contains(pathLower, "www.")

}

// Extract SSl/TLS Certificate Info Of Domain
func (c *Crawler) extractCertificate(ctx context.Context, domain string, nf *config.NodeFeatures) error {
	// 1. Create a dialer and establish a raw TCP connection using the context.
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", domain+":443")
	if err != nil {
		return fmt.Errorf("tcp dial failed: %w", err)
	}
	defer rawConn.Close()

	// 2. Create a TLS client connection on top of the raw connection.
	tlsConfig := &tls.Config{
		ServerName:         domain, // It's good practice to set the ServerName for SNI.
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	defer tlsConn.Close()

	// 3. Perform the TLS handshake with context awareness.
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("tls handshake failed: %w", err)
	}

	// 4. Proceed with extracting certificate info from the established connection.
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("no peer certificates found")
	}

	cert := certs[0]
	nf.IsCertValid = cert.NotAfter.After(time.Now())
	nf.IsHTTPS = true
	nf.CertAgeDays = int(time.Since(cert.NotBefore).Hours() / 24) // ⬅️ ADD THIS LINE

	if len(cert.Subject.Country) > 0 {
		nf.CertCountry = cert.Subject.Country[0]
	} else if len(cert.Issuer.Country) > 0 {
		nf.CertCountry = cert.Issuer.Country[0]
	}

	nf.CertIssuerOrg = common.GetIssuerOrganization(cert)
	nf.CertReliability = common.MapReliabilityScore(common.GetCertReliability(cert, nf.CertIssuerOrg))

	return nil
}

// Extract Whois Info Of Domain
func (c *Crawler) extractWhois(ctx context.Context, domain string, nf *config.NodeFeatures) (err error) {
	// Use the apex domain for WHOIS lookups
	apexDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return fmt.Errorf("could not determine apex domain for '%s': %w", domain, err)
	}

	// Add a defer function to recover from panics in the parser library.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered from panic in whoisparser for domain %s: %v", apexDomain, r)
		}
	}()

	layout := "2006-01-02T15:04:05Z"

	type whoisResult struct {
		raw string
		err error
	}
	resultChan := make(chan whoisResult, 1)

	go func() {
		// Always perform the WHOIS lookup on the apex domain.
		raw, err := whois.Whois(apexDomain)
		resultChan <- whoisResult{raw: raw, err: err}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err() // Context timed out or was cancelled
	case res := <-resultChan:
		if res.err != nil {
			return fmt.Errorf("whois lookup for '%s' failed: %w", apexDomain, res.err)
		}

		// The panic happens in the next line. The defer will catch it.
		result, parseErr := whoisparser.Parse(res.raw)
		if parseErr != nil {
			return fmt.Errorf("whoisparser for '%s' failed: %w", apexDomain, parseErr)
		}

		nf.HasWhois = true
		// Creation Date
		if createdDate, ok := common.ParseWhoisDate(result.Domain.CreatedDate); ok {
			nf.DomainCreationDate = createdDate.Format(layout)
			nf.DomainAge = int(time.Since(createdDate).Hours() / 24 / 365)
		}

		// Expiration Date
		if expirationDate, ok := common.ParseWhoisDate(result.Domain.ExpirationDate); ok {
			nf.DomainEndPeriod = expirationDate.Format(layout)
		}

		// 	// Creation Date
		// 	if result.Domain.CreatedDate != "" {
		// 		createdDate, fallback := common.RegexpDateTime(result.Domain.CreatedDate)
		// 		if fallback == "" {
		// 			nf.DomainCreationDate = createdDate.Format(layout)
		// 			nf.DomainAge = int(time.Since(createdDate).Hours() / 24 / 365)
		// 		} else {
		// 			parsed, _ := time.Parse(layout, fallback)
		// 			nf.DomainCreationDate = parsed.Format(layout)
		// 			nf.DomainAge = int(time.Since(parsed).Hours() / 24 / 365)
		// 		}
		// 	}

		// 	// Expiration Date
		// 	if result.Domain.ExpirationDate != "" {
		// 		expirationDate, fallback := common.RegexpDateTime(result.Domain.ExpirationDate)
		// 		if fallback == "" {
		// 			nf.DomainEndPeriod = expirationDate.Format(layout)
		// 		} else {
		// 			// Corrected typo from time.parse to time.Parse
		// 			parsed, _ := time.Parse(layout, fallback)
		// 			nf.DomainEndPeriod = parsed.Format(layout)
		// 		}
		// 	}
	}
	return nil
}

// extract text from an HTML node and its children
func extractText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	if n.Type != html.ElementNode {
		return ""
	}
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		b.WriteString(extractText(c))
	}
	// Replace newlines and trim whitespace for cleaner CSV output
	return strings.TrimSpace(strings.ReplaceAll(b.String(), "\n", " "))
}

// Extract info about a domain after crawling it
func (c *Crawler) crawlAndExtractPageContent(ctx context.Context, url *neturl.URL, res *config.NodeFeatures) error {
	target := url.String()
	res.Redirects = 0

	// Parse the URL
	parsedURL, err := neturl.Parse(target)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		res.IsErrorPage = true
		return fmt.Errorf("failed to create http request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		res.IsErrorPage = true
		return fmt.Errorf("http get failed: %w", err)
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	// We can get the final URL after redirects from the response's request object.
	// This is useful if the original URL was, e.g., http and it redirected to https.
	finalURL := resp.Request.URL.String()
	res.URL = finalURL // Update the feature with the final URL.
	if finalURL != target {
		// A simple way to know if at least one redirect happened.
		res.Redirects = 1 // Or some other non-zero indicator.
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		res.IsValidHTML = false
		return nil
	}
	res.IsValidHTML = true

	// Prepare for parsing elements
	refs := []config.Ref{}
	wordSet := map[string]struct{}{}
	wordLenSum := 0
	wordCount := 0

	// Define irrelevant extensions
	irrelevantExtensions := map[string]bool{
		".css": true, ".js": true, ".ico": true,
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".svg": true,
	}

	// Get the canonical URL for the source page itself to check for self-loops
	sourceCanonicalURL := common.CanonicalizeURL(parsedURL)

	// Recursive DOM walker to extract data
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				res.AnchorsCount++
				for _, a := range n.Attr {
					if a.Key == "href" {
						href := a.Val
						if u, err := neturl.Parse(href); err == nil {
							abs := parsedURL.ResolveReference(u)

							// --- FILTERING LOGIC ---
							// 1. Canonicalize the target URL
							targetCanonicalURL := common.CanonicalizeURL(abs)

							// 2. Check for irrelevant file extensions
							ext := filepath.Ext(abs.Path)
							if irrelevantExtensions[ext] {
								continue // Skip this irrelevant link
							}

							// 3. Check for self-loops
							if targetCanonicalURL == sourceCanonicalURL {
								res.SelfAnchorsCount++ // You already count these, so just skip adding the edge
								continue
							}

							// If the link is valid, add it to the references
							refs = append(refs, config.Ref{
								URL:          targetCanonicalURL, // Use the canonical URL
								IsSameDomain: abs.Host == parsedURL.Host,
								IsAnchor:     true,
							})
						}
					}
					if a.Key == "onmouseover" {
						res.UseMouseover++
					}
				}
			case "form":
				res.FormsCount++
				res.HasFormWithURL = true
				for _, a := range n.Attr {
					if a.Key == "action" {
						action := a.Val
						if u, err := neturl.Parse(action); err == nil {
							abs := parsedURL.ResolveReference(u)
							refs = append(refs, config.Ref{
								URL:          abs.String(),
								IsSameDomain: abs.Host == parsedURL.Host,
								IsForm:       true,
							})
						}
					}
				}
			case "iframe":
				res.HasIframe = true
				for _, a := range n.Attr {
					if a.Key == "src" {
						src := a.Val
						if u, err := neturl.Parse(src); err == nil {
							abs := parsedURL.ResolveReference(u)
							refs = append(refs, config.Ref{
								URL:          abs.String(),
								IsSameDomain: abs.Host == parsedURL.Host,
								IsIframe:     true,
							})
						}
					}
				}
			case "script":
				res.JavaScriptCount++
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode {
						if common.LooksLikeObfuscatedJS(c.Data) {
							res.ObfuscatedJavaScriptCount++
						}
					}
				}
			}
		}
		if n.Type == html.TextNode {
			// Collect words for stats
			words := strings.Fields(n.Data)
			for _, w := range words {
				wordSet[w] = struct{}{}
				wordLenSum += len(w)
				wordCount++
			}
		}
		// Visit children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	if wordCount > 0 {
		res.MeanWordLength = wordLenSum / wordCount
	}
	res.DistinctWordsCount = len(wordSet)
	res.Refs = refs

	// // Simple phishing heuristic
	// if res.HasFormWithURL || res.HasIframe || res.UseMouseover > 0 ||
	// 	res.Redirects > 2 || res.JavaScriptCount > 5 || res.ObfuscatedJavaScriptCount > 0 {
	// 	res.IsPhishing = true
	// }

	return nil
}

// Extract spf, dmarc, and general DNS record presence
func (c *Crawler) lookupDNS(ctx context.Context, domain string, nf *config.NodeFeatures) error {
	dnsc := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	// Use ExchangeContext instead of Exchange
	in, _, err := dnsc.ExchangeContext(ctx, &m, "8.8.8.8:53")
	if err != nil {
		return err
	}

	// If the response code is NOERROR, it means the domain exists in DNS,
	// even if there are no TXT records. This is a reliable check for HasDNSRecord.
	if in.Rcode == dns.RcodeSuccess {
		nf.HasDNSRecord = true
	}

	// Now, specifically check for SPF and DMARC records in the answer.
	for _, a := range in.Answer {
		if t, ok := a.(*dns.TXT); ok {
			for _, txt := range t.Txt {
				if strings.HasPrefix(txt, "v=spf1") {
					nf.HasSPF = true
				} else if strings.Contains(txt, "dmarc") {
					nf.HasDMARC = true
				}
			}
		}
	}
	return nil
}

// Reading a file contain urls
func ReadURLsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not open file: %w", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rawURL := scanner.Text()
		if rawURL != "" {
			urls = append(urls, common.NormalizeURL(rawURL))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("file contained no valid URLs")
	}

	return urls, nil
}

// It now reads the PhishTank CSV and filters for verified, online phishing sites.
func ReadphishtankURLsFromFile(filePath string) ([]phishtankURL, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not open file: %w", err)
	}
	defer file.Close()

	var urls []phishtankURL
	reader := csv.NewReader(file)

	// Find the column indexes from the header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("could not read header row: %w", err)
	}

	colIndex := make(map[string]int)
	for i, colName := range header {
		colIndex[colName] = i
	}

	// Verify required columns exist
	requiredCols := []string{"url", "verified", "online"}
	for _, col := range requiredCols {
		if _, ok := colIndex[col]; !ok {
			return nil, fmt.Errorf("required column '%s' not found in CSV header", col)
		}
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading CSV record: %w", err)
		}

		// Filter for verified and online phishing sites
		isVerified := record[colIndex["verified"]] == "yes"
		isOnline := record[colIndex["online"]] == "yes"

		if isVerified && isOnline {
			url := record[colIndex["url"]]
			if url != "" {
				// Use the new helper function
				normalizedURL := common.NormalizeURL(url)
				urls = append(urls, phishtankURL{URL: normalizedURL, Label: true})
			}
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("file contained no valid (verified and online) phishing URLs")
	}

	return urls, nil
}
