# Trivy UI Documentation

## User documentation

- [User guide](user-guide/README.md)
- [Installation and configuration](user-guide/01-installation.md)
- [Authentication and access control](user-guide/02-authentication-and-access-control.md)
- [Multi-cluster collection](user-guide/03-multi-cluster-collection.md)
- [Dashboard features and navigation](user-guide/05-dashboard-features-and-navigation.md)
- [Operations and troubleshooting](user-guide/04-operations-and-troubleshooting.md)


## Project documentation

- [Review notes](dev/review/README.md)
- [Dashboard design proposal](dev/dashboard-design-proposal.md)

The user guide describes the supported deployment model: the backend collects
reports cluster-wide, Kubernetes RBAC limits the backend ServiceAccount, and
Dashboard scopes limit authenticated users.
