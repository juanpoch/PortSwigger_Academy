# Introducción a XML y vulnerabilidades XXE

Extensible Markup Language (**XML**) es un lenguaje de marcado enfocado en almacenar y estructurar información. Es ampliamente utilizado para el intercambio de datos entre aplicaciones web, especialmente en APIs antiguas o en entornos empresariales complejos.

Un archivo XML está compuesto por etiquetas jerárquicas. El primer elemento se denomina *root element*, y los siguientes son *child elements*.

### Ejemplo de archivo XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>     <!-- Declaración -->
<email>                                    <!-- Root element -->
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body>
</email>
```

---

## Document Type Definition (DTD)

XML puede validar su estructura mediante un esquema denominado **DTD** (Document Type Definition). Puede estar embebido en el mismo archivo o ser externo.

### DTD embebido para el ejemplo anterior:

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

### DTD externo:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```

O referenciado por URL:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

---

## XML Entities y External Entities

Las *entities* en XML actúan como variables. Se definen en el DTD y pueden representar texto estático o contenido de archivos externos o URLs.

### Entity interna (texto reutilizable):

```xml
<!ENTITY company "Inlane Freight">
```

### External Entity:

```xml
<!ENTITY company SYSTEM "http://localhost/company.txt">
<!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
```

Cuando un archivo XML incluye una entity referenciada, el **XML parser** la reemplaza con su contenido. Si el parser está mal configurado y permite cargar entidades externas, esto puede llevar a filtrado de archivos locales (*local file disclosure*) o incluso SSRF.

---

## Caracteres especiales en XML

Algunos caracteres deben ser reemplazados por *entity references*:

| Carácter | Entity   |
| -------- | -------- |
| `<`      | `&lt;`   |
| `>`      | `&gt;`   |
| `&`      | `&amp;`  |
| `"`      | `&quot;` |
| `'`      | `&apos;` |

---

## Vulnerabilidad XXE (XML External Entity)

Cuando un servidor procesa archivos XML sin desactivar ciertas funcionalidades peligrosas del parser (como la carga de entidades externas), un atacante puede explotar esta funcionalidad para:

* Leer archivos internos del sistema (`/etc/passwd`)
* Realizar solicitudes HTTP arbitrarias (SSRF)
* Exfiltrar información hacia servidores bajo su control
* Provocar errores deliberados que revelan datos internos

### Ejemplo de payload XXE para leer `/etc/passwd`:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

Este payload define una entidad externa llamada `xxe` cuyo contenido es el archivo `/etc/passwd`, y luego lo invoca en un nodo visible de la respuesta.

---

## 🚨 Advertencia de seguridad

Los parsers XML, por defecto, permiten funcionalidades peligrosas como `external entities`, `parameter entities` y `DTD validation`. Estas deben ser desactivadas para prevenir **XXE**.

---

## 🔎 Lecciones clave

* Nunca procesar archivos XML sin sanitizarlos ni restringir el parser
* Desactivar `DOCTYPE` y `ENTITY` si no son necesarios
* Usar parsers seguros y configuraciones actualizadas (por ejemplo, desactivar `resolve-entities` en lxml o Java SAX)
* Las vulnerabilidades XXE se pueden encadenar con otras, como SSRF

---

