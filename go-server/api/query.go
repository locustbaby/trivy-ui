package api

import (
	"fmt"
	"strings"
	"sync"
)

type ReportQuery struct {
	Type           string
	Cluster        string
	Namespaces     []string
	Search         string
	OnlyVulnerable bool
	Page           int
	PageSize       int
	Sort           string
}

type QueryResult struct {
	Total               int
	WithVulnerabilities int
	Items               []Report
}

type QueryService interface {
	ListReports(q ReportQuery) QueryResult
}

type queryServiceImpl struct {
	cache CacheService
}

var queryResultCache sync.Map

func NewQueryService(cache CacheService) QueryService {
	return &queryServiceImpl{cache: cache}
}

func (s *queryServiceImpl) ListReports(q ReportQuery) QueryResult {
	cacheKey := queryResultCacheKey(q, getTypeVersion(q.Type))
	if cached, ok := queryResultCache.Load(cacheKey); ok {
		if result, ok := cached.(QueryResult); ok {
			return result
		}
	}

	allReports := s.cache.GetReports(q.Type, q.Cluster, q.Namespaces)
	if len(allReports) == 0 {
		result := QueryResult{Items: []Report{}}
		queryResultCache.Store(cacheKey, result)
		return result
	}

	hasSearch := q.Search != ""
	if !hasSearch && !q.OnlyVulnerable {
		total := len(allReports)
		withVuln := 0
		for _, r := range allReports {
			if hasVulnerabilitiesInReport(r) {
				withVuln++
			}
		}

		result := QueryResult{
			Total:               total,
			WithVulnerabilities: withVuln,
			Items:               paginateReports(allReports, q.Page, q.PageSize),
		}
		queryResultCache.Store(cacheKey, result)
		return result
	}

	var filtered []Report
	withVulnerabilities := 0
	searchLower := strings.ToLower(q.Search)

	for _, r := range allReports {
		hasVuln := hasVulnerabilitiesInReport(r)

		if q.OnlyVulnerable && !hasVuln {
			continue
		}

		if hasSearch && !reportMatchesSearch(r, searchLower) {
			continue
		}

		filtered = append(filtered, r)
		if hasVuln {
			withVulnerabilities++
		}
	}

	result := QueryResult{
		Total:               len(filtered),
		WithVulnerabilities: withVulnerabilities,
		Items:               paginateReports(filtered, q.Page, q.PageSize),
	}
	queryResultCache.Store(cacheKey, result)
	return result
}

func queryResultCacheKey(q ReportQuery, version uint64) string {
	return fmt.Sprintf("%s|%s|%s|%s|%t|%d|%d|%d",
		q.Type,
		q.Cluster,
		strings.Join(q.Namespaces, ","),
		strings.ToLower(q.Search),
		q.OnlyVulnerable,
		q.Page,
		q.PageSize,
		version,
	)
}

func paginateReports(reports []Report, page, pageSize int) []Report {
	total := len(reports)
	if total == 0 {
		return []Report{}
	}
	start := (page - 1) * pageSize
	if start >= total {
		return []Report{}
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return reports[start:end]
}

func reportMatchesSearch(report Report, searchLower string) bool {
	if strings.Contains(strings.ToLower(report.Name), searchLower) ||
		strings.Contains(strings.ToLower(report.Cluster), searchLower) ||
		strings.Contains(strings.ToLower(report.Namespace), searchLower) {
		return true
	}

	dataMap, ok := report.Data.(map[string]interface{})
	if !ok {
		return false
	}

	var artifact interface{}
	if reportData, found := dataMap["report"]; found {
		if reportDataMap, ok := reportData.(map[string]interface{}); ok {
			artifact = reportDataMap["artifact"]
		}
	}
	if artifact == nil {
		artifact = dataMap["artifact"]
	}
	artifactMap, ok := artifact.(map[string]interface{})
	if !ok {
		return false
	}
	repository, ok := artifactMap["repository"].(string)
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(repository), searchLower)
}
