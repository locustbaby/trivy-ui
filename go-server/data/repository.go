package data

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"trivy-ui/config"
)

// Repository manages report operations
type Repository struct {
	db *DB
}

// NewRepository creates a new repository
func NewRepository(db *DB) *Repository {
	return &Repository{db: db}
}

// GetDB returns the database instance
func (r *Repository) GetDB() *DB {
	return r.db
}

// SaveReport saves a report to the database
func (r *Repository) SaveReport(report *Report) error {
	// Log the report data for debugging
	fmt.Printf("Saving report: %+v\n", report)

	// Marshal the data to JSON
	dataJSON, err := json.Marshal(report.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal report data: %v", err)
	}

	// Log the JSON data for debugging
	fmt.Printf("Raw data to save: %s\n", string(dataJSON))

	// Check if report exists
	existingReport, err := r.GetReport(report.Type, report.Cluster, report.Namespace, report.Name)
	if err != nil && err.Error() != "report not found" {
		return err
	}

	now := time.Now()
	if existingReport != nil {
		// Update existing report
		_, err = r.db.db.Exec(`
			UPDATE reports
			SET status = ?, data = ?, updated_at = ?
			WHERE type = ? AND cluster = ? AND namespace = ? AND name = ?
		`, report.Status, string(dataJSON), now, report.Type, report.Cluster, report.Namespace, report.Name)
	} else {
		// Insert new report
		_, err = r.db.db.Exec(`
			INSERT INTO reports (type, cluster, namespace, name, status, data, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, report.Type, report.Cluster, report.Namespace, report.Name, report.Status, string(dataJSON), now, now)
	}

	if err != nil {
		return fmt.Errorf("failed to save report: %v", err)
	}

	return nil
}

// GetReport retrieves a report by type, cluster, namespace, and name
func (r *Repository) GetReport(reportType config.ReportType, cluster, namespace, name string) (*Report, error) {
	var report Report
	var dataJSON string
	var createdAt, updatedAt time.Time

	err := r.db.db.QueryRow(`
		SELECT type, cluster, namespace, name, status, data, created_at, updated_at
		FROM reports
		WHERE type = ? AND cluster = ? AND namespace = ? AND name = ?
	`, reportType, cluster, namespace, name).Scan(
		&report.Type, &report.Cluster, &report.Namespace, &report.Name,
		&report.Status, &dataJSON, &createdAt, &updatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("report not found")
		}
		return nil, fmt.Errorf("failed to get report: %v", err)
	}

	// Log the raw data for debugging
	fmt.Printf("Raw data from database: %s\n", dataJSON)

	// Unmarshal the data
	if err := json.Unmarshal([]byte(dataJSON), &report.Data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal report data: %v", err)
	}

	// Set timestamps
	report.CreatedAt = createdAt
	report.UpdatedAt = updatedAt

	// Log the unmarshaled data for debugging
	fmt.Printf("Unmarshaled data: %+v\n", report.Data)

	return &report, nil
}

// DeleteReport deletes a report by type, cluster, namespace, and name
func (r *Repository) DeleteReport(reportType config.ReportType, cluster, namespace, name string) error {
	query := `
		DELETE FROM reports
		WHERE type = ? AND cluster = ? AND namespace = ? AND name = ?
	`
	result, err := r.db.db.Exec(query, reportType, cluster, namespace, name)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("report not found")
	}

	return nil
}

// IsReportExpired checks if a report is older than the given duration
func (r *Repository) IsReportExpired(report *Report, maxAge time.Duration) bool {
	// If report is nil, consider it expired
	if report == nil {
		return true
	}

	// Check if the report's updated_at timestamp is older than maxAge
	return time.Since(report.UpdatedAt) > maxAge
}

// GetReports retrieves reports based on query parameters
func (r *Repository) GetReports(query ReportQuery) (*ReportResponse, error) {
	// Build the base query
	baseQuery := `
		SELECT type, cluster, namespace, name,
			status, data, created_at, updated_at
		FROM reports
		WHERE type = ?
	`
	args := []interface{}{query.Type}

	// Add cluster filter if provided
	if len(query.Clusters) > 0 {
		placeholders := make([]string, len(query.Clusters))
		for i := range query.Clusters {
			placeholders[i] = "?"
			args = append(args, query.Clusters[i])
		}
		baseQuery += " AND cluster IN (" + strings.Join(placeholders, ",") + ")"
	}

	// Add namespace filter if provided
	if len(query.Namespaces) > 0 {
		placeholders := make([]string, len(query.Namespaces))
		for i := range query.Namespaces {
			placeholders[i] = "?"
			args = append(args, query.Namespaces[i])
		}
		baseQuery += " AND namespace IN (" + strings.Join(placeholders, ",") + ")"
	}

	// Add ordering
	baseQuery += " ORDER BY created_at DESC"

	// Execute the query
	rows, err := r.db.db.Query(baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Process results
	var reports []*Report
	for rows.Next() {
		var report Report
		var data []byte
		var createdAt, updatedAt time.Time

		err := rows.Scan(
			&report.Type,
			&report.Cluster,
			&report.Namespace,
			&report.Name,
			&report.Status,
			&data,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(data, &report.Data); err != nil {
			return nil, err
		}

		report.CreatedAt = createdAt
		report.UpdatedAt = updatedAt
		reports = append(reports, &report)
	}

	return &ReportResponse{
		Reports: reports,
		Total:   len(reports),
		Page:    1,
		Pages:   1,
	}, nil
}
