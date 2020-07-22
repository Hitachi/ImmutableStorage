module immSvc

go 1.14

replace immutil => ../../immutil

require (
	immutil v0.0.0-00010101000000-000000000000
	k8s.io/api v0.18.3
	k8s.io/apimachinery v0.18.3
)
