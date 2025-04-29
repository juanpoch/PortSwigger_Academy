## 📍 Dónde buscar Path Traversal

Esta vulnerabilidad afecta principalmente a funciones que leen archivos del sistema mediante rutas proporcionadas por el usuario, como `?file=...`, `?page=...`, `?template=...`, etc.

Además del caso típico de la etiqueta `<img>` con un parámetro dinámico, existen otros lugares comunes donde buscar posibles vectores de path traversal:

---

### 1. 🖼️ Cargas de imágenes o archivos estáticos
- `/image?filename=pic.jpg`
- `/download?file=report.pdf`
- `/view?img=logo.png`

👉 Cualquier recurso que cargue archivos visibles por el usuario es sospechoso.

---

### 2. 📄 Templates o páginas dinámicas
- `/?page=about.html`
- `/load?template=header.tpl`
- `/content?file=article1.html`

👉 Son vectores clásicos donde el servidor podría incluir archivos sin validación adecuada.

---

### 3. 🧾 Reportes, logs, backups
- `/logs?file=access.log`
- `/backup?file=db.sql`
- `/admin/view?logfile=...`

👉 Muy comunes en áreas administrativas o internas, donde a veces la validación es más laxa.

---

### 4. 🎧 Recursos multimedia
- `/stream?media=song.mp3`
- `/video?path=intro.mp4`
- `/music?track=rock1.mp3`

---

### 5. 💾 Descarga de archivos adjuntos
- `/attachments?name=invoice.pdf`
- `/getfile?doc=contract.docx`

---

### 6. ⚙️ APIs internas o endpoints ocultos
- `/api/load?config=config.yaml`
- `/system/loadfile?target=settings.json`

👉 Aparecen frecuentemente en Swagger, JavaScript frontend o archivos `.map`.

---

### 7. 🧠 Parámetros menos obvios
- `/editor?loadfile=...`
- `/lang?load=spanish.lang`
- `/data?src=data1.csv`

👉 No siempre usan `file=`, a veces usan nombres más genéricos o camuflados.

---

## 🧪 Tips prácticos para detectar path traversal

| Técnica | ¿Qué buscar? |
|:--------|:-------------|
| Buscar parámetros como `file`, `filename`, `path`, `template`, `page`, `doc`, `load`, `read`, `src`, `log`, `lang`, `content`, `include` | Son nombres típicos de parámetros vulnerables. |
| Revisar archivos JS | Muchas rutas internas se exponen en el
