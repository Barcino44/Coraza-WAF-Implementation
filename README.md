# Documentación

El presente repositorio cuenta con 3 archivos claves para el correcto desempeño del WAF.

##  ``main.go``

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
