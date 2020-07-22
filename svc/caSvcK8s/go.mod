module caSvc

go 1.14

replace immutil => ../../immutil

require (
	immutil v0.0.0-00010101000000-000000000000
	github.com/imdario/mergo v0.3.9 // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d // indirect
	golang.org/x/time v0.0.0-20200416051211-89c76fbcd5d1 // indirect
	k8s.io/api v0.18.3
	k8s.io/apimachinery v0.18.3
)
