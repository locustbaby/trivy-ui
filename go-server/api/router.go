package api

import (
	"net/http"
	"net/url"
	"os"
	"strings"

	"trivy-ui/auth"
	"trivy-ui/config"
	"trivy-ui/dataaccess"
	"trivy-ui/kubernetes"

	httpSwagger "github.com/swaggo/http-swagger"
)

type Router struct {
	mux       *http.ServeMux
	handler   *Handler
	errorPage *customErrorPage
}

func NewRouter(k8sClient *kubernetes.Client, staticPath string, cache CacheService, clusterReg *ClusterRegistry, crdReg *config.CRDRegistry, authService *auth.Service, dataPolicy *dataaccess.Policy) *Router {
	r := &Router{
		mux:       http.NewServeMux(),
		handler:   NewHandler(k8sClient, cache, clusterReg, NewQueryService(cache), crdReg, authService, dataPolicy),
		errorPage: newCustomErrorPage(os.Getenv("ERROR_PAGE_FILE")),
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

	r.mux.HandleFunc("/api/v1/overview", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			r.handler.GetOverview(w, req)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	r.mux.HandleFunc("/api/v1/overview/trends", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			r.handler.GetOverviewTrends(w, req)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	r.mux.HandleFunc("/api/v1/reports", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			r.handler.GetReportsV1(w, req)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	r.mux.HandleFunc("/api/v1/reports/detail", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			r.handler.GetReportDetails(w, req)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	r.mux.HandleFunc("/api/v1/reports/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/api/v1/reports/")
		parts := strings.Split(path, "/")
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			if len(parts) == 4 {
				cluster, err := url.PathUnescape(parts[0])
				if err != nil {
					http.NotFound(w, req)
					return
				}
				typeName, err := url.PathUnescape(parts[1])
				if err != nil {
					http.NotFound(w, req)
					return
				}
				namespace, err := url.PathUnescape(parts[2])
				if err != nil {
					http.NotFound(w, req)
					return
				}
				reportName, err := url.PathUnescape(parts[3])
				if err != nil {
					http.NotFound(w, req)
					return
				}
				if namespace == "_" {
					namespace = ""
				}
				r.handler.GetReportDetailsByRef(w, req, cluster, typeName, namespace, reportName)
				return
			}
			http.NotFound(w, req)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	r.mux.HandleFunc("/api/report-types", r.handler.GetReportTypes)
	// Canonical v1 aliases. Legacy routes above remain for one compatibility cycle.
	r.mux.HandleFunc("/api/v1/report-types", r.handler.GetReportTypes)
	r.mux.HandleFunc("/api/v1/clusters", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			r.handler.GetClusters(w, req)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
	r.mux.HandleFunc("/api/v1/clusters/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/api/v1/clusters/")
		parts := strings.Split(path, "/")
		if len(parts) == 2 && parts[1] == "namespaces" && (req.Method == http.MethodGet || req.Method == http.MethodOptions) {
			r.handler.GetNamespacesByCluster(w, req, parts[0])
			return
		}
		http.NotFound(w, req)
	})

	r.mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost || req.Method == http.MethodOptions {
			r.handler.Login(w, req)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
	r.mux.HandleFunc("/api/auth/logout", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost || req.Method == http.MethodOptions {
			r.handler.Logout(w, req)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
	r.mux.HandleFunc("/api/auth/me", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			r.handler.Me(w, req)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
	r.mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost || req.Method == http.MethodOptions {
			r.handler.Login(w, req)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
	r.mux.HandleFunc("/api/v1/auth/logout", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost || req.Method == http.MethodOptions {
			r.handler.Logout(w, req)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
	r.mux.HandleFunc("/api/v1/auth/me", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || req.Method == http.MethodOptions {
			r.handler.Me(w, req)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

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

	r.mux.HandleFunc("/api/v1/error-page", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodOptions {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cfg := GetErrorPageConfig()
		if cfg == nil {
			writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Success", Data: map[string]interface{}{"enabled": false}})
			return
		}
		writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Success", Data: map[string]interface{}{
			"enabled": true,
			"title":   cfg.Title,
			"message": cfg.Message,
			"items":   cfg.Items,
		}})
	})

	// Operator-provided custom error page (public, hot-reloadable).
	if r.errorPage != nil {
		r.mux.HandleFunc("/error-page.html", r.errorPage.handler)
	}

	// 健康检查端点
	r.mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// 就绪检查端点
	r.mux.HandleFunc("/readyz", r.handler.ReadinessCheck)

	// 缓存统计端点
	r.mux.HandleFunc("/api/cache/stats", r.handler.GetCacheStats)

	r.mux.HandleFunc("/", SpaHandler(staticPath))

}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	public := path == "/healthz" || path == "/readyz" || path == "/error-page.html" || path == "/api/v1/error-page" || strings.HasPrefix(path, "/api/auth/") || strings.HasPrefix(path, "/api/v1/auth/") || (!strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/swagger/"))
	handler := http.Handler(r.mux)
	if r.handler.auth != nil && r.handler.auth.IsEnabled() {
		if !public {
			handler = r.handler.AuthMiddleware(handler)
		}
	} else {
		handler = r.handler.AccessContextMiddleware(handler)
	}
	AccessLogHandler(handler).ServeHTTP(w, req)
}
