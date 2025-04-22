package data

import (
	"fmt"
	"time"

	"trivy-ui/config"
)

// Report represents a vulnerability or compliance report
type Report struct {
	Type      config.ReportType `json:"type"`
	Cluster   string            `json:"cluster"`
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Status    string            `json:"status,omitempty"`
	Data      interface{}       `json:"data"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// String returns a string representation of the report
func (r *Report) String() string {
	return fmt.Sprintf("Report{Type: %s, Cluster: %s, Namespace: %s, Name: %s, Status: %s, Data: %+v}",
		r.Type, r.Cluster, r.Namespace, r.Name, r.Status, r.Data)
}

// Cluster represents a Kubernetes cluster
type Cluster struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Namespace represents a Kubernetes namespace
type Namespace struct {
	Cluster     string    `json:"cluster"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ReportQuery represents a query for reports
type ReportQuery struct {
	Type       config.ReportType `json:"type"`
	Clusters   []string          `json:"clusters,omitempty"`
	Namespaces []string          `json:"namespaces,omitempty"`
	Page       int               `json:"page"`
	PageSize   int               `json:"page_size"`
}

// ReportResponse represents a paginated response of reports
type ReportResponse struct {
	Reports []*Report `json:"reports"`
	Total   int       `json:"total"`
	Page    int       `json:"page"`
	Pages   int       `json:"pages"`
}
