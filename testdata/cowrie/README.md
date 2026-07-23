# Fixtures de Cowrie

`sesion-ejemplo.json` son eventos reales capturados por Cowrie el 2026-07-22
en el servidor de desarrollo: 3 intentos de conexion SSH fallidos desde
203.0.113.7 (generados a proposito para validar el formato).

Cubre los 6 tipos de evento del ciclo basico de una sesion:
`session.connect`, `client.version`, `client.kex`, `client.fingerprint`,
`login.failed`, `session.closed`.

Sirve para desarrollar y testear el collector sin necesidad de tener el
honeypot levantado. Un evento por linea (JSON Lines).
