package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"phishcrawler/pkg/cmd"
	"phishcrawler/pkg/config"
	"sync"
	"time"
	// "phishcrawler/pkg/db"
)

// CrawlJob remains the same.
type CrawlJob struct {
	URL             string
	Depth           int
	IsPhishingLabel *bool // Pointer allows for nil when no label exists
}

// It just processes jobs until the jobs channel is closed.
func worker(id int, crawler *cmd.Crawler, jobs <-chan CrawlJob, results chan<- *config.NodeFeatures, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel() // Ensure cancel is called for every job

		features, err := crawler.ExtractFeatures(ctx, job.URL, job.Depth, job.IsPhishingLabel)
		if err != nil {
			// Even with a critical error, ExtractFeatures returns a partial features object.
			// Log the error but still send the features to be processed.
			log.Printf("Worker %d: CRITICAL error processing %s: %v", id, job.URL, err)
		}

		// Always send the result, even if it's a partial one with errors noted.
		// This is crucial for decrementing the inFlightJobs counter.
		results <- features
	}
}

// func worker(id int, crawler *cmd.Crawler, jobs <-chan CrawlJob, results chan<- *config.NodeFeatures, wg *sync.WaitGroup) {
// 	defer wg.Done()
// 	for job := range jobs {
// 		// log.Printf("Worker %d: Processing URL %s (Depth: %d)", id, job.URL, job.Depth)
// 		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)

// 		features, err := crawler.ExtractFeatures(ctx, job.URL, job.Depth, job.IsPhishingLabel)
// 		if err != nil {
// 			// log.Printf("Worker %d: CRITICAL error for %s: %v. Skipping.", id, job.URL, err)
// 			cancel()
// 			continue
// 		}

// 		if features != nil {
// 			results <- features
// 		}
// 		cancel()
// 	}
// }


func main() {
	log.SetOutput(os.Stderr)

	// --- MODIFICATION: Remove old flags and add new -savecsv flag ---
	saveCSV := flag.Bool("savecsv", false, "Set to true to save output to default CSV files (data/nodes.csv, data/edges.csv)")
	urlStr := flag.String("url", "", "A single URL to crawl directly.")
	urlsFile := flag.String("urls", "", "Path to file with URL(s) (discovery mode)")
	phishtankURLsFile := flag.String("phtkdata", "", "Path to CSV of Phishtank dataset file for training data generation")
	outputJSON := flag.Bool("opjs", false, "Set to true to also output results as JSON to stdout (default false)")
	urldepth := flag.Int("depth", 1, "Set the maximum crawl depth")
	workers := flag.Int("w", 70, "Number of concurrent workers")
	isPhishingFlag := flag.Bool("isphish", false, "When used with -urls or -url, treat the URL(s) as phishing")
	flag.Parse()

	if *urldepth < 1 {
		log.Fatalf("Error: depth must be a positive integer (>= 1).")
	}

	if *urlsFile == "" && *phishtankURLsFile == "" && *urlStr == "" {
		log.Println("Usage: go run main.go -url <url_string> OR -u <urls_file.txt> OR -phtkdata <data.csv> ...")
		flag.PrintDefaults()
		return
	}

	var nodeWriter, edgeWriter *cmd.CSVWriter

	// Conditional writer setup based on the -savecsv flag ---
	if *saveCSV {
		var err error
		var isNewNodeFile, isNewEdgeFile bool

		// Use hardcoded file paths
		nodeFilePath := "nodes.csv"
		edgeFilePath := "edges.csv"

		nodeWriter, isNewNodeFile, err = cmd.NewCSVWriter(nodeFilePath)
		if err != nil {
			log.Fatalf("Failed to initialize nodes CSV writer: %v", err)
		}
		defer nodeWriter.Close()

		edgeWriter, isNewEdgeFile, err = cmd.NewCSVWriter(edgeFilePath)
		if err != nil {
			log.Fatalf("Failed to initialize edges CSV writer: %v", err)
		}
		defer edgeWriter.Close()

		if isNewNodeFile {
			nodeWriter.WriteHeader(config.NodeFeatures{}.GetCSVHeader())
		}
		if isNewEdgeFile {
			edgeWriter.WriteHeader(config.EdgeCSVHeader)
		}

		log.Printf("Saving node features to %s\n", nodeFilePath)
		log.Printf("Saving graph edges to %s\n", edgeFilePath)
	}

	crawler, err := cmd.NewCrawler()
	if err != nil {
		log.Fatalf("Failed to create crawler: %v", err)
	}

	jobs := make(chan CrawlJob)
	results := make(chan *config.NodeFeatures)
	var workerWg sync.WaitGroup

	workerWg.Add(*workers)
	for w := 1; w <= *workers; w++ {
		go worker(w, crawler, jobs, results, &workerWg)
	}

	go func() {
		var inFlightJobs int
		var jobQueue []CrawlJob
		var successCount int

		if *phishtankURLsFile != "" {
			log.Printf("Starting in phishtank data mode from file: %s", *phishtankURLsFile)
			phishtankSeeds, err := cmd.ReadphishtankURLsFromFile(*phishtankURLsFile)
			if err != nil {
				log.Fatalf("Error reading phishtank URLs from file: %v", err)
			}
			for _, seed := range phishtankSeeds {
				if crawler.CheckAndAdd(seed.URL) {
					label := seed.Label
					jobQueue = append(jobQueue, CrawlJob{URL: seed.URL, Depth: 1, IsPhishingLabel: &label})
				}
			}
		} else if *urlStr != "" {
			log.Printf("Starting in single URL mode: %s", *urlStr)
			if *isPhishingFlag {
				log.Println("NOTE: -isphish flag is active. This URL will be labeled as phishing.")
			}
			if crawler.CheckAndAdd(*urlStr) {
				var label *bool
				if *isPhishingFlag {
					isPhish := true
					label = &isPhish
				}
				jobQueue = append(jobQueue, CrawlJob{URL: *urlStr, Depth: 1, IsPhishingLabel: label})
			}
		} else if *urlsFile != "" {
			log.Printf("Starting in discovery mode from file: %s", *urlsFile)
			if *isPhishingFlag {
				log.Println("NOTE: -isphish flag is active. All URLs from this file will be labeled as phishing.")
			}
			seedURLs, err := cmd.ReadURLsFromFile(*urlsFile)
			if err != nil {
				log.Fatalf("Error reading URLs from file: %v", err)
			}
			for _, url := range seedURLs {
				if crawler.CheckAndAdd(url) {
					var label *bool
					if *isPhishingFlag {
						isPhish := true
						label = &isPhish
					}
					jobQueue = append(jobQueue, CrawlJob{URL: url, Depth: 1, IsPhishingLabel: label})
				}
			}
		}

		processResult := func(res *config.NodeFeatures) {
			inFlightJobs--
			if res == nil {
				log.Println("Received a nil result, likely due to a critical parsing error. Skipping.")
				return
			}
			successCount++

			if nodeWriter != nil {
				nodeWriter.WriteRow(res.ToCSVRow())
			}
			if edgeWriter != nil {
				for _, ref := range res.Refs {
					edgeWriter.WriteRow(ref.ToEdgeCSVRow(res.URL))
				}
			}

			if *outputJSON {
				jsonData, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(jsonData))
			}
			if res.Depth < *urldepth {
				for _, ref := range res.Refs {
					if crawler.CheckAndAdd(ref.URL) {
						jobQueue = append(jobQueue, CrawlJob{URL: ref.URL, Depth: res.Depth + 1})
					}
				}
			}
		}

		for len(jobQueue) > 0 || inFlightJobs > 0 {
			var activeJob CrawlJob
			var jobsChan chan CrawlJob

			if len(jobQueue) > 0 {
				activeJob = jobQueue[0]
				jobsChan = jobs
			}

			select {
			case jobsChan <- activeJob:
				jobQueue = jobQueue[1:]
				inFlightJobs++
			case res := <-results:
				processResult(res)
			}
		}

		log.Printf("Phishcrawler finished completely. Processed %d pages.\n", successCount)
		close(jobs)
	}()

	workerWg.Wait()
	log.Println("All workers have finished.")
}