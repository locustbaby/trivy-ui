package api

import (
	"net/http"
	"strings"

	"trivy-ui/kubernetes"

	httpSwagger "github.com/swaggo/http-swagger"
)

type Router struct {
	mux     *http.ServeMux
	handler *Handler
}

func NewRouter(k8sClient *kubernetes.Client, staticPath string) *Router {
	r := &Router{
		mux:     http.NewServeMux(),
		handler: NewHandler(k8sClient),
	}
	r.Setup(staticPath)
	return r
}

func (r *Router) Setup(staticPath string) {
	r.mux.HandleFunc("/api/v1/type", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			r.handler.GetTypesV1(w, req)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	r.mux.HandleFunc("/api/v1/type/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/api/v1/type/")
		parts := strings.Split(path, "/")
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			if len(parts) == 1 {
				r.handler.GetReportsByTypeV1(w, req, parts[0])
			} else if len(parts) == 2 {
				r.handler.GetReportDetailsV1(w, req, parts[0], parts[1])
			} else {
				http.NotFound(w, req)
			}
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	r.mux.HandleFunc("/api/report-types", r.handler.GetReportTypes)

	r.mux.HandleFunc("/api/clusters", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			r.handler.GetClusters(w, req)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	r.mux.HandleFunc("/api/clusters/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/api/clusters/")
		parts := strings.Split(path, "/")
		if len(parts) == 2 && parts[1] == "namespaces" && (req.Method == http.MethodGet || req.Method == http.MethodOptions) {
			cluster := parts[0]
			r.handler.GetNamespacesByCluster(w, req, cluster)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	r.mux.Handle("/swagger/", httpSwagger.WrapHandler)

	r.mux.HandleFunc("/", SpaHandler(staticPath))
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}
