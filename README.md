# voc-feeds

Consolida cada hora los feeds oficiales de avisos de seguridad de Palo Alto, Cisco, Fortinet, Microsoft, Ivanti y Citrix en `data/feeds.json`, que lee Radar VOC.

- Solo contiene información pública de los fabricantes.
- `sources` indica, por fabricante, si el feed se pudo leer en la última corrida y por qué no, si falló.
- Para correrlo a mano: pestaña **Actions** → *Actualizar feeds de fabricantes* → **Run workflow**.
