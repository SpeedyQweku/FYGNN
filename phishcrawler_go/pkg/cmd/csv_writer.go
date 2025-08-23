package cmd

import (
	"encoding/csv"
	"fmt"
	"os"
)

// CSVWriter wraps the standard csv.Writer to provide a clean interface.
type CSVWriter struct {
	file   *os.File
	writer *csv.Writer
}

// NewCSVWriter creates a new CSV file and returns a writer instance.
func NewCSVWriter(filePath string) (*CSVWriter, bool, error) {
	// Check file status to see if it's a new file.
	_, err := os.Stat(filePath)
	isNewFile := os.IsNotExist(err)

	// Open the file in append mode. Create it if it doesn't exist.
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open or create CSV file: %w", err)
	}

	writer := csv.NewWriter(file)

	return &CSVWriter{
		file:   file,
		writer: writer,
	}, isNewFile, nil
}


// WriteHeader writes the header row to the CSV file.
func (cw *CSVWriter) WriteHeader(header []string) error {
	return cw.writer.Write(header)
}

// WriteRow writes a single data row to the CSV file.
func (cw *CSVWriter) WriteRow(row []string) error {
	return cw.writer.Write(row)
}

// Close flushes any buffered data to the file and closes it.
// This is a critical step to ensure all data is saved.
// func (cw *CSVWriter) Close() error {
// 	// Flush writes any buffered data to the underlying io.Writer.
// 	cw.writer.Flush()
// 	if err := cw.writer.Error(); err != nil {
// 		// Attempt to close the file anyway, but prioritize the flush error.
//         _ = cw.file.Close()
// 		return fmt.Errorf("error flushing CSV writer: %w", err)
// 	}

// 	return cw.file.Close()
// }

func (cw *CSVWriter) Close() error {
	cw.writer.Flush()
	flushErr := cw.writer.Error()
	closeErr := cw.file.Close()

	if flushErr != nil {
		return fmt.Errorf("error flushing CSV writer: %w", flushErr)
	}
	if closeErr != nil {
		return fmt.Errorf("error closing CSV file: %w", closeErr)
	}
	return nil
}