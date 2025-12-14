package config

type ReportKind struct {
	Name       string `json:"name"`
	ShortName  string `json:"shortName"`
	APIVersion string `json:"apiVersion"`
	Namespaced bool   `json:"namespaced"`
	Kind       string `json:"kind"`
}

func AllReports() []ReportKind {
	registry := GetGlobalRegistry()
	return registry.GetAllReports()
}

func GetReportByName(name string) *ReportKind {
	registry := GetGlobalRegistry()
	return registry.GetReportByName(name)
}
