module github.com/XeroAPI/xerogolang

replace (
	github.com/XeroAPI/xerogolang => ./github.com/ninja-software/xerogolang
	github.com/XeroAPI/xerogolang/accounting => ./github.com/ninja-software/xerogolang/accounting
)

require (
	github.com/golang/protobuf v1.3.2 // indirect
	github.com/gorilla/mux v1.6.2
	github.com/gorilla/pat v0.0.0-20180118222023-199c85a7f6d1
	github.com/gorilla/sessions v1.1.1
	github.com/kr/pretty v0.1.0 // indirect
	github.com/markbates/goth v1.49.0
	github.com/mrjones/oauth v0.0.0-20180629183705-f4e24b6d100c
	github.com/ninja-software/xoauthlite v0.0.0-20200409052549-daa0bb429f17
	github.com/stretchr/testify v1.5.1
	golang.org/x/net v0.0.0-20190613194153-d28f0bde5980 // indirect
	golang.org/x/oauth2 v0.0.0-20181017192945-9dcd33a902f4
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v2 v2.2.5 // indirect
)

go 1.13
