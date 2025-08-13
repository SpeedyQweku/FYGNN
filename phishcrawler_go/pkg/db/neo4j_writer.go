package db


import (
	"context"
	"fmt"
	"phishcrawler/pkg/config" // Make sure this import path is correct for your project

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Neo4jWriter handles the connection and writing to the Neo4j database.
type Neo4jWriter struct {
	driver neo4j.DriverWithContext
}

// NewNeo4jWriter creates and initializes a new Neo4jWriter instance.
func NewNeo4jWriter(uri, username, password string) (*Neo4jWriter, error) {
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return nil, fmt.Errorf("could not create neo4j driver: %w", err)
	}

	// Verify the connection to the database
	ctx := context.Background()
	if err := driver.VerifyConnectivity(ctx); err != nil {
		return nil, fmt.Errorf("could not verify neo4j connectivity: %w", err)
	}
	fmt.Println("Successfully connected to Neo4j.")

	return &Neo4jWriter{driver: driver}, nil
}

// Close closes the database driver connection.
func (nw *Neo4jWriter) Close(ctx context.Context) {
	nw.driver.Close(ctx)
}

// WriteNode creates or updates a website node in the database.
func (nw *Neo4jWriter) WriteNode(ctx context.Context, features *config.NodeFeatures) error {
	session := nw.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	props, err := featuresToMap(features)
	if err != nil {
		return err
	}

	_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		query := `
            MERGE (w:Website {url: $url})
            ON CREATE SET w = $props
            ON MATCH SET w += $props
        `
		_, err := tx.Run(ctx, query, map[string]any{
			"url":   features.URL,
			"props": props,
		})
		return nil, err
	})

	return err
}

// WriteEdge creates a relationship between two website nodes.
func (nw *Neo4jWriter) WriteEdge(ctx context.Context, sourceURL string, ref *config.Ref) error {
	session := nw.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// *** MODIFIED: Pass the sourceURL into refToMap ***
		edgeProps, err := refToMap(ref, sourceURL)
		if err != nil {
			return nil, err
		}

		query := `
            MATCH (source:Website {url: $source_url})
            MATCH (target:Website {url: $target_url})
            MERGE (source)-[r:LINKS_TO]->(target)
            SET r = $props
        `
		_, err = tx.Run(ctx, query, map[string]any{
			"source_url": sourceURL,
			"target_url": ref.URL,
			"props":      edgeProps,
		})
		return nil, err
	})

	return err
}

// featuresToMap remains the same as before...
func featuresToMap(features *config.NodeFeatures) (map[string]any, error) {
	return map[string]any{
		"url":                    features.URL,
		"url_length":             features.URLLength,
		"domain":                 features.Domain,
		"domain_url_length":      features.DomainURLLength,
		"subdomain_count":        features.SubdomainCount,
		"path_segment_count":     features.PathSegmentCount,
		"path_starts_with_url":   features.PathStartsWithURL,
		"has_at_symbol":          features.HasAtSymbol,
		"dashes_count":           features.DashesCount,
		"sensitive_words_in_url": features.SensitiveWords,
		"is_ip_address":          features.IsIPAddress,
		"digit_letter_ratio":     features.DigitLetterRatio,
		"uses_homograph_trick":   features.UsesHomographTrick,
		"has_random_looking_str": features.HasRandomLookingStr,
		"contains_encoded_chars": features.ContainsEncodedChars,
		"is_https":                 features.IsHTTPS,
		"is_cert_valid":            features.IsCertValid,
		"cert_country":             features.CertCountry,
		"cert_reliability":         features.CertReliability,
		"cert_issuer_organization": features.CertIssuerOrg,
		"has_spf":                  features.HasSPF,
		"has_dmarc":                features.HasDMARC,
		"domain_age":           features.DomainAge,
		"domain_creation_date": features.DomainCreationDate,
		"domain_end_period":    features.DomainEndPeriod,
		"has_dns_record":       features.HasDNSRecord,
		"has_whois":            features.HasWhois,
		"is_valid_html":           features.IsValidHTML,
		"is_error_page":           features.IsErrorPage,
		"anchors_count":           features.AnchorsCount,
		"forms_count":             features.FormsCount,
		"javascript_count":        features.JavaScriptCount,
		"obfuscated_js_count":     features.ObfuscatedJavaScriptCount,
		"self_anchors_count":      features.SelfAnchorsCount,
		"has_form_with_url":       features.HasFormWithURL,
		"has_iframe":              features.HasIframe,
		"use_mouseover":           features.UseMouseover,
		"mean_word_length":     features.MeanWordLength,
		"distinct_words_count": features.DistinctWordsCount,
		"status_code": features.StatusCode,
		"redirects":   features.Redirects,
		"is_phishing": features.IsPhishing,
		"depth":       features.Depth,
	}, nil
}


// refToMap converts the Ref struct into a map for edge properties.
// *** MODIFIED: Added sourceURL as a parameter and a property in the returned map. ***
func refToMap(ref *config.Ref, sourceURL string) (map[string]any, error) {
    // var anchorText string
    // if ref.AnchorText != "" {
    //     anchorText = ref.AnchorText
    // } else {
    //     anchorText = "NULL"
    // }
    return map[string]any{
        "source_url":     sourceURL, // Added this line
        "target_url":     ref.URL,   // Renamed "url" to "target_url" for clarity
        "is_same_domain": ref.IsSameDomain,
        "is_form":        ref.IsForm,
        "is_anchor":      ref.IsAnchor,
        "is_iframe":      ref.IsIframe,
        // "anchor_text":    anchorText,
    }, nil
}