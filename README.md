# Documentación

El presente repositorio cuenta con 3 archivos claves para el correcto desempeño del WAF.

##  ``main.go``

- Contiene dependencias necesarias para la inicialización del WAF como reverse proxy.
- Carga un archivo de configuración `` @coraza.conf-recommended `` con parámetros recomendados por coraza para la inicialización del WAF.
- Carga un archivo setup `` @crs-setup.conf.example `` con reglas customizables que permiten establecer el comportamiento del WAF frente a amenazas.
- Carga una carpeta `` @owasp_crs/*.conf `` que contiene configuraciones usadas por el WAF para la detección de diversos ataques como SQLi-XSS, etc.
