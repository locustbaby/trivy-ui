# Trivy UI Dashboard

A web-based UI for visualizing and managing Trivy vulnerability scan results in Kubernetes clusters.

## Overview
Trivy UI provides a centralized dashboard for viewing vulnerability reports generated by the Trivy Operator in Kubernetes environments. It offers an intuitive interface to browse, search, and analyze security vulnerabilities detected in your container images.

## Screenshots

### Dashboard Overview
![Dashboard Overview](./trivy-dashboard/public/trivy-dashboard.png)
*Main dashboard showing vulnerability statistics and summary*

### Report Details
![Report Details](./trivy-dashboard/public/report-details.png)
*In-depth view of individual vulnerability reports*


## Features
- **Dashboard View**: Overview of vulnerability statistics across namespaces
- **Detailed Reports**: In-depth analysis of vulnerabilities by severity
- **Search & Filter**: Quickly locate specific vulnerability reports
- **Caching**: Optimized performance with disk-persistent caching
- **Responsive Design**: Works on desktop and mobile devices

## Architecture
The application consists of two main components:

- **Frontend**: Vue 3 single-page application with Vite
- **Backend**: Go server that interfaces with the Kubernetes API

```
trivy-ui/
├── go-server/         # Go backend application
│   ├── api/           # API handlers
│   ├── cache/         # Caching functionality
│   └── kubernetes/    # Kubernetes client interface
└── my-trivy-dashboard/   # Vue 3 frontend
    └── src/           # Frontend source code
```

## Prerequisites
- Go 1.19+
- Node.js 16+
- Access to a Kubernetes cluster with Trivy Operator installed
- kubectl configured with appropriate permissions

## Installation
### Build from Source
1. Clone the repository
```shell
git clone https://github.com/locustbaby/trivy-ui.git
cd trivy-ui
```
2. Build and run the frontend
```shell
cd trivy-dashboard
npm install
npm run build
```
3. Build and run the backend server
```shell
cd ../go-server
go build
./go-server
```
4. Access the dashboard at http://localhost:8080

### Run into Kubernetes
1. Create a ServiceAccount and ClusterRoleBinding
```shell
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: trivy-ui
rules:
- apiGroups:
  - ""
  resources:
  - namespaces
  verbs:
  - get
  - list
- apiGroups:
  - aquasecurity.github.io
  resources:
  - clustercompliancereports
  - clusterconfigauditreports
  - clusterinfraassessmentreports
  - clusterrbacassessmentreports
  - clustersbomreports
  - clustervulnerabilityreports
  - configauditreports
  - exposedsecretreports
  - infraassessmentreports
  - rbacassessmentreports
  - sbomreports
  - vulnerabilityreports
  verbs:
  - get
  - list
EOF

kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: trivy-ui
EOF
```

2. Deploy the Trivy UI application
```shell
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: trivy-ui
  name: trivy-ui
spec:
  replicas: 1
  selector:
    matchLabels:
      app: trivy-ui
  template:
    metadata:
      labels:
        app: trivy-ui
    spec:
      containers:
      - env:
        - name: STATIC_PATH
          value: trivy-dashboard/dist
        image: <image>
        name: trivy-ui
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        resources:
          limits:
            memory: 64Mi
          requests:
            memory: 64Mi
      dnsPolicy: ClusterFirst
      restartPolicy: Always
EOF
```

3. Create Ingress and Service
```shell
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  labels:
    app: trivy-ui
  name: trivy-ui
spec:
    ports:
    - name: http
      port: 80
      targetPort: 8080
    selector:
      app: trivy-ui
    type: ClusterIP
EOF

kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
  labels:
    app: trivy-ui
  name: trivy-ui
spec:
  ingressClassName: nginx
  rules:
  - host: trivy-ui.example.com
    http:
      paths:
      - backend:
          service:
            name: trivy-ui
            port:
              number: 8080
        path: /
        pathType: Prefix
  tls:
  - hosts:
    - trivy-ui.example.com
    secretName: trivy-ui-tls
EOF
```

## Environment Variables
The server can be configured using the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | HTTP port to listen on | 8080 |
| DEBUG | Enable debug logging | false |
| CACHE_PATH | Path to save cache data | trivy-cache.dat |
| CACHE_INTERVAL | How often to save cache to disk in minutes | 2 |
| STATIC_PATH | Path to static frontend assets | ../trivy-dashboard/dist |
| KUBECONFIG | Path to Kubernetes config file | ~/.kube/config |

## Development

### Backend (Go)
The backend server provides APIs for accessing Trivy vulnerability reports from Kubernetes.
```shell
cd go-server
go run main.go
```

### Frontend (Vue 3)
For frontend development with hot reload.
```shell
cd trivy-dashboard
npm run dev
```

### Docker Images

Docker images are automatically built and pushed to Docker Hub when a new tag is pushed. You can pull a specific version using:

```shell
docker pull locustbaby/trivy-ui:v0.0.1
```

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
- Trivy - The vulnerability scanner
- Trivy Operator - Kubernetes operator for Trivy
- Vue.js - Frontend framework
- Go - Backend language