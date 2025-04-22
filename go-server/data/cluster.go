package data

import (
	"database/sql"
	"fmt"
	"time"
)

// ClusterRepository manages cluster and namespace operations
type ClusterRepository struct {
	db *DB
}

// NewClusterRepository creates a new cluster repository
func NewClusterRepository(db *DB) *ClusterRepository {
	return &ClusterRepository{db: db}
}

// SaveCluster saves a cluster to the database
func (r *ClusterRepository) SaveCluster(cluster *Cluster) error {
	query := `
		INSERT OR REPLACE INTO clusters (
			name, description, updated_at
		)
		VALUES (?, ?, ?)
	`
	_, err := r.db.db.Exec(query,
		cluster.Name,
		cluster.Description,
		time.Now(),
	)
	return err
}

// GetCluster retrieves a cluster by name
func (r *ClusterRepository) GetCluster(name string) (*Cluster, error) {
	query := `
		SELECT name, description, created_at, updated_at
		FROM clusters
		WHERE name = ?
	`
	var cluster Cluster
	var createdAt, updatedAt time.Time

	err := r.db.db.QueryRow(query, name).Scan(
		&cluster.Name,
		&cluster.Description,
		&createdAt,
		&updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("cluster not found")
	}
	if err != nil {
		return nil, err
	}

	cluster.CreatedAt = createdAt
	cluster.UpdatedAt = updatedAt
	return &cluster, nil
}

// GetClusters retrieves all clusters
func (r *ClusterRepository) GetClusters() ([]*Cluster, error) {
	query := `
		SELECT name, description, created_at, updated_at
		FROM clusters
		ORDER BY name
	`
	rows, err := r.db.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clusters []*Cluster
	for rows.Next() {
		var cluster Cluster
		var createdAt, updatedAt time.Time

		err := rows.Scan(
			&cluster.Name,
			&cluster.Description,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, err
		}

		cluster.CreatedAt = createdAt
		cluster.UpdatedAt = updatedAt
		clusters = append(clusters, &cluster)
	}

	return clusters, nil
}

// DeleteCluster deletes a cluster by name
func (r *ClusterRepository) DeleteCluster(name string) error {
	query := `
		DELETE FROM clusters
		WHERE name = ?
	`
	result, err := r.db.db.Exec(query, name)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("cluster not found")
	}

	return nil
}

// SaveNamespace saves a namespace to the database
func (r *ClusterRepository) SaveNamespace(namespace *Namespace) error {
	query := `
		INSERT OR REPLACE INTO namespaces (
			cluster, name, description, updated_at
		)
		VALUES (?, ?, ?, ?)
	`
	_, err := r.db.db.Exec(query,
		namespace.Cluster,
		namespace.Name,
		namespace.Description,
		time.Now(),
	)
	return err
}

// GetNamespace retrieves a namespace by cluster and name
func (r *ClusterRepository) GetNamespace(cluster, name string) (*Namespace, error) {
	query := `
		SELECT cluster, name, description, created_at, updated_at
		FROM namespaces
		WHERE cluster = ? AND name = ?
	`
	var namespace Namespace
	var createdAt, updatedAt time.Time

	err := r.db.db.QueryRow(query, cluster, name).Scan(
		&namespace.Cluster,
		&namespace.Name,
		&namespace.Description,
		&createdAt,
		&updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("namespace not found")
	}
	if err != nil {
		return nil, err
	}

	namespace.CreatedAt = createdAt
	namespace.UpdatedAt = updatedAt
	return &namespace, nil
}

// GetNamespaces retrieves all namespaces for a cluster
func (r *ClusterRepository) GetNamespaces(cluster string) ([]*Namespace, error) {
	query := `
		SELECT cluster, name, description, created_at, updated_at
		FROM namespaces
		WHERE cluster = ?
		ORDER BY name
	`
	rows, err := r.db.db.Query(query, cluster)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var namespaces []*Namespace
	for rows.Next() {
		var namespace Namespace
		var createdAt, updatedAt time.Time

		err := rows.Scan(
			&namespace.Cluster,
			&namespace.Name,
			&namespace.Description,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, err
		}

		namespace.CreatedAt = createdAt
		namespace.UpdatedAt = updatedAt
		namespaces = append(namespaces, &namespace)
	}

	return namespaces, nil
}

// GetAllNamespaces retrieves all namespaces
func (r *ClusterRepository) GetAllNamespaces() ([]*Namespace, error) {
	query := `
		SELECT cluster, name, description, created_at, updated_at
		FROM namespaces
		ORDER BY cluster, name
	`
	rows, err := r.db.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var namespaces []*Namespace
	for rows.Next() {
		var namespace Namespace
		var createdAt, updatedAt time.Time

		err := rows.Scan(
			&namespace.Cluster,
			&namespace.Name,
			&namespace.Description,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, err
		}

		namespace.CreatedAt = createdAt
		namespace.UpdatedAt = updatedAt
		namespaces = append(namespaces, &namespace)
	}

	return namespaces, nil
}

// DeleteNamespace deletes a namespace by cluster and name
func (r *ClusterRepository) DeleteNamespace(cluster, name string) error {
	query := `
		DELETE FROM namespaces
		WHERE cluster = ? AND name = ?
	`
	result, err := r.db.db.Exec(query, cluster, name)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("namespace not found")
	}

	return nil
}
