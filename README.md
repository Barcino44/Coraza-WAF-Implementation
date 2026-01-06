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

## Paso #1: Instalación de módulos.

Los módulos presentes en el archivo ``go.mod`` deben ser instalados con ayuda de

````
go mod tidy
````

## Paso #2: Configuración adicional de archivos.

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

El archivo ``@crs-setup.conf.example`` cuenta con reglas customizables para conseguir aumentar o disminuir la estrictez del WAF. 

Entre las configuraciones realizadas se encuentran.

### ***Registro de eventos***

En este caso se habilitan los logs en tiempo real en fase 1 y fase 2)

````.go
SecDefaultAction "phase:1,log,auditlog,pass"  
SecDefaultAction "phase:2,log,auditlog,pass" 
````

### ***Nivel de paranoia***

El nivel de paranoia, es un parámetro que permite configurar la rigurosidad del WAF. Un mayor nivel de paranoia puede resultar en una mayor identificación de amenazas. Sin embargo también puede acarrear una mayor cantidad de FP clasificando como amenazas a peticiones que pueden no ser dañinas. De acuerdo con la documentación de Coraza.

***- Nivel 1:*** El nivel de paranoia 1 es el predeterminado. En este nivel, la mayoría de las reglas básicas están habilitadas. PL1 se recomienda para principiantes e instalaciones con requerimientos de seguridad básicos. La cantidad de FP en este nivel son muy bajas.

***- Nivel 2:*** El nivel de paranoia 2 incluye muchas reglas adicionales, por ejemplo, la habilitación de muchas protecciones contra inyecciones de SQL y XSS basadas en expresiones regulares, y la adición de palabras clave adicionales para la verificación de inyecciones de código.

***- Nivel 3:*** El nivel de paranoia 3 habilita más reglas y listas de palabras clave, y límites en el uso de caracteres especiales. PL3 está dirigido a usuarios con experiencia en el manejo de FP y sitios con requerimientos de alta seguridad.

***- Nivel 4:*** El nivel de paranoia 4 restringe aún más los caracteres especiales. Se recomienda el nivel más alto para usuarios con experiencia que protegen instalaciones con requisitos de seguridad muy altos. PL4 probablemente generará una gran cantidad de FP que deberán ser tratados.

Para nuestro caso, se modificará el nivel de paranoia a nivel 2 con el fin de aumentar un poco más la rigidez por defecto y evitar una gran cantidad de bypasses. 

````.go
SecAction \
    "id:900001,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.20.0',\
    setvar:tx.detection_paranoia_level=2"
````

Además, se pueden establecer un nivel de paranoia para la identificación de amenazas ``setvar:tx.detection_paranoia_level=2`` y otro para el bloqueo de las mismas ``setvar:tx.blocking_paranoia_level=2``. No obstante, unicamente el nivel establecido en la variable ``setvar:tx.blocking_paranoia_level=2`` tendrá incidencia en el ``anomaly-score`` que será usado para determinar si una petición es bloqueada o no. El nivel de detection debe ser mayor o igual al nivel de bloqueo.

````.go
SecAction \
    "id:900001,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.20.0',\
    setvar:tx.detection_paranoia_level=2"
````

### ***Procesador de cuerpo***

El WAF por defecto confia en el parametro de la cabecera ``Content-Type`` para realizar el procesamiento de la petición. Sin embargo, algunas veces este parámetro no es establecido o trae información incorrecorrecta lo que afecta el procesamiento del WAF. Por tal motivo, se habilita el procesador de cuerpo con el fin de que el WAF realice su procesamiento basado también en el contenido del cuerpo.

````.go
SecAction \
    "id:900010,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.20.0',\
    setvar:tx.enforce_bodyproc_urlencoded=1"
````

### ***Anomaly-score***

El anomaly-score permite determinar que requests deben ser bloqueadas. El WAF evalua cada petición con el conjunto de reglas CRS configuradas en la carpeta ``owasp_crs/*.conf`` y el nivel de paranoia establecido. Las reglas pueden tener un diferente nivel de severidad, entre estas se encuentran.

***- Severidad CRÍTICA: Puntuación de anomalía de 5.*** Generado principalmente por las reglas de ataque de la aplicación (archivos 93x y 94x).

***- Severidad de ERROR: Puntuación de anomalía de 4.*** Generado principalmente por las reglas de fuga de salida (archivos 95x).

***- Severidad de ADVERTENCIA: Puntuación de anomalía de 3.*** Generado principalmente por las reglas de cliente malicioso (archivos 91x).

***- Severidad de AVISO: Puntuación de anomalía de 2.*** Generado principalmente por las reglas de protocolo (archivos 92x).

Debido a que una sola petición puede hacer 'match' con más de una regla del CRS, el ``anomaly-score`` total de una petición es la suma del ``anomaly score`` de cada regla 'matcheada'. 

La configuración de coraza recomienda matener un valor bajo en el ``anomaly score`` si lo que se busca es ser más restrictivo. 

<p align="center">
	<img width="589" height="222" alt="image" src="https://github.com/user-attachments/assets/3b4514d4-3a8c-4e22-b47d-9395d43208a9" />
</p>

Por tal motivo, se mantendrá un  ``anomaly score = 5`` tanto para las peticiones (inbounds) como respuestas del servidor (outbounds).

````.go
SecAction \                                                                                                                                               
    "id:900110,\                                                                                                                                          
    phase:1,\                                                                                                                                             
    pass,\                                                                                                                                                
    t:none,\                                                                                                                                              
    nolog,\                                                                                                                                               
    tag:'OWASP_CRS',\                                                                                                                                     
    ver:'OWASP_CRS/4.20.0',\                                                                                                                              
    setvar:tx.inbound_anomaly_score_threshold=5,\                                                                                                         
    setvar:tx.outbound_anomaly_score_threshold=5" 
````

### ***Versionado del setup***

Finalmente, se establece la versión del setup del crs.

````.go
SecAction \
    "id:900990,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.20.0',\
    setvar:tx.crs_setup_version=4200"
````

### ***Posibles configuraciones adicionales***

Además de las presentes  ``@crs-setup.conf.example`` ofrece variables customizables para el WAF entre las que se encuentran.

- Reporte de anomalias basado en el ``anomaly score``

- Bloqueo temprano de anomalías (Sin necesidad que una petición pase por todas las fases).

- Plugins adicionales.

- Restricción de tamaño de cabeceras.

- Restricción de caracteres.

- Entre otros.

Por ahora, estas configuraciones se mantendrán con sus valores por defecto al no ser tan relevantes.
