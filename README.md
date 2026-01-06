# Documentación

## 1. Explicación de los archivos presentes

El presente repositorio cuenta con 3 archivos claves para el correcto desempeño del WAF.

###  ``main.go``

````.go
package main

import (
    "fmt"
    "log"
    "net/http"
    "net/http/httputil"
    "net/url" 
    coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
    "github.com/corazawaf/coraza/v3"
    txhttp "github.com/corazawaf/coraza/v3/http"
    "github.com/corazawaf/coraza/v3/types"
)

func main() {
    waf := createWAF()
    
    targetURL, err := url.Parse("http://192.168.1.11:80")
    if err != nil {
        log.Fatal(err)
    }
    
    proxy := httputil.NewSingleHostReverseProxy(targetURL)
    
    proxy.ModifyResponse = func(resp *http.Response) error {
        resp.Header.Set("X-Protected-By", "Coraza-WAF")
        return nil
    }
    
    handler := txhttp.WrapHandler(waf, proxy)
    http.Handle("/", handler)
    
    fmt.Println("Coraza WAF Reverse Proxy escuchando en :8090")
    log.Fatal(http.ListenAndServe(":8090", nil))
}

func createWAF() coraza.WAF { 
    waf, err := coraza.NewWAF(
        coraza.NewWAFConfig().
            WithRootFS(coreruleset.FS).
            WithErrorCallback(logError).
            WithDirectives("Include @coraza.conf-recommended").
            WithDirectives("Include @crs-setup.conf.example").
            WithDirectives("Include @owasp_crs/*.conf"),
    )
    if err != nil {
        log.Fatal(err)
    }
    return waf
}

func logError(mr types.MatchedRule) {
    fmt.Printf(
        "[WAF][%s] RuleID=%d Msg=%s\n",
        mr.Rule().Severity(),
        mr.Rule().ID(),
        mr.Message(),
    )
}
````

- Contiene dependencias necesarias para la inicialización del WAF como reverse proxy.
- Carga un archivo de configuración `` @coraza.conf-recommended `` con parámetros recomendados por coraza para la inicialización del WAF.
- Carga un archivo setup `` @crs-setup.conf.example `` con reglas customizables que permiten establecer el comportamiento del WAF frente a amenazas.
- Carga una carpeta `` @owasp_crs/*.conf `` que contiene configuraciones usadas por el WAF para la detección de diversos ataques como SQLi-XSS, etc.
- Imprime logs a medida que se testea y existen coincidencias con una regla.

###  ``go.mod``

````
module coraza-waf-proxy

go 1.23.0

require (
	github.com/corazawaf/coraza-coreruleset/v4 v4.20.0
	github.com/corazawaf/coraza/v3 v3.3.3
)

require (
	github.com/corazawaf/libinjection-go v0.2.2 // indirect
	github.com/magefile/mage v1.15.1-0.20241126214340-bdc92f694516 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20240411101913-e07a1f0e8eb4 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valllabh/ocsf-schema-golang v1.0.3 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)
````
Contiene los módulos de go necesarios para el correcto funcionamiento de WAF.

###  ``go.sum``

Para el control criptográfico y de versiones de los módulos instalados.

## Implementación

### Paso #1: Instalación de módulos.

Los módulos presentes en el archivo ``go.mod`` deben ser instalados con ayuda de

````
go mod tidy
````

### Paso #2: Configuración adicional de archivos.

La instalación de los módulos del paso anterior trae consigo la creación de la carpeta ``/go/pkg/mod/github.com/corazawaf/coraza-coreruleset/v4@v4.20.0/rules``.

Dicha carpeta contiene los archivos ``@..`` mecionados en ``main.go``. Estos archivos pueden ser modificados a conveniencia para conseguir que el WAF sea más o menos restrictivo.

<p align="center">
    <img width="973" height="66" alt="image" src="https://github.com/user-attachments/assets/1db2f122-1b66-4f44-a42e-3d9333d88798" />
</p>

### Paso #2.1: Configuración de ``@coraza.conf-recommended``

Este archivo contiene la configuración inicial recomendada por coraza. Entre los aspectos más importantes se encuentran:

- Añade reglas que permiten al WAF realizar el manejo de respuestas basado en el cuerpo de la petición. 
- Añade reglas para garantizar el comportamiento óptimo ante peticiones en JSON o XML.
- Añade reglas adicionales como el tamaño máximo del curepo, etc.

Mantendremos la configuración por defecto. Unicamente se cambiará la variable ``SecRuleEngine`` de ``DetectionOnly`` a ``On`` para habilitar la función bloqueante del WAF.

<p align="center">
    <img width="787" height="164" alt="image" src="https://github.com/user-attachments/assets/de197e3d-690f-4110-bc41-3dbc2a596003" />
</p>

### Paso #2.2: Configuración de ``@crs-setup.conf.example``

