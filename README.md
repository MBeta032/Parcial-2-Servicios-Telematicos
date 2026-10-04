# 🔐 Servicios Seguros: FTPS, DNS sobre TLS y SFTP detrás de un Firewall UFW

**Segundo Parcial · Servicios Telemáticos · Universidad Autónoma de Occidente**
Octubre de 2026

| Integrante | Código |
|---|:---:|
| Manuel Betancurt Perez | `2236320` |
| Sharon Zuray Abella Dias | `2236364` |
| Alan Yesid Basante Portilla | `2236708` |

Tres servicios cifrados montados con Vagrant sobre Ubuntu 22.04, con un firewall UFW como único punto de entrada.

**Temas:** firewall UFW · reenvío de puertos (DNAT y MASQUERADE) · CA propia y certificados X.509 con OpenSSL · FTPS con vsftpd · DNS sobre TLS con systemd-resolved · SFTP enjaulado con OpenSSH · análisis de tráfico con Wireshark

| Parte | Servicio | Máquina | Valor |
|:---:|---|---|:---:|
| 1 | FTPS con vsftpd, protegido por UFW | srv1 y srv2 | 2.0 |
| 2 | DNS sobre TLS con systemd-resolved | cliente | 1.5 |
| 3 | SFTP sobre OpenSSH, protegido por UFW | srv1 y srv2 | 1.5 |

---

## 🗺️ Topología

```
Cliente (FileZilla / Ubuntu)        srv1-2236320 (UFW)                 srv2-2236320 (vsftpd + SFTP)
                                    eth2: 192.168.1.40
   red local   ---------------->    DNAT + MASQUERADE
   puertos 21, 50000-50010, 2222    eth1: 192.168.50.3  -- red privada -->  eth1: 192.168.50.2
                                                                            UFW: solo acepta a srv1
```

| Máquina | Hostname | Interfaces | Rol |
|---|---|---|---|
| srv1 | `srv1-2236320` | `eth1` 192.168.50.3 (red privada) · `eth2` 192.168.1.40 (Public Network) | Firewall UFW, único punto de entrada |
| srv2 | `srv2-2236320` | `eth1` 192.168.50.2 (red privada) | vsftpd (FTPS) y SFTP, con UFW propio |
| cliente | `cli-2236320` | `eth1` 192.168.1.41 (Public Network) | Cliente de DoT, `openssl s_client` y `sftp` |

> [!NOTE]
> La dirección usada como `<ip pública>` es **192.168.1.40**, la `eth2` de srv1, entregada por DHCP en la red local.

### Reenvíos configurados en srv1

| Puerto externo | Destino | Servicio |
|:---:|---|---|
| `21/tcp` | 192.168.50.2:21 | FTPS, canal de control |
| `50000-50010/tcp` | 192.168.50.2, mismo puerto | FTPS, canal de datos en modo pasivo |
| `2222/tcp` | 192.168.50.2:22 | SFTP |

### Archivos del repositorio

| Archivo | Máquina | Para qué |
|---|:---:|---|
| `Vagrantfile` | host | Define las tres máquinas, la red privada y la Public Network |
| `srv1/before.rules` | srv1 | Reglas NAT: DNAT de los puertos 21, 50000-50010 y 2222, y MASQUERADE |
| `srv1/user.rules` | srv1 | Reglas creadas con `ufw`: 22/tcp y las tres `ufw route allow` |
| `srv1/sysctl.conf` | srv1 | Reenvío IP habilitado (`net/ipv4/ip_forward=1`) |
| `srv2/vsftpd.conf` | srv2 | FTPS con TLS explícito y modo pasivo |
| `srv2/sshd_config` | srv2 | Usuario `sftp_2236320` enjaulado con `internal-sftp` |
| `srv2/user.rules` | srv2 | Reglas creadas con `ufw`: solo se acepta a srv1 |
| `srv2/before.rules` | srv2 | Ping entrante en `DROP` |
| `cliente/resolved.conf` | cliente | DNS sobre TLS |
| `certs/ca.crt` | srv2 | Certificado de la CA propia |
| `certs/servidor.crt` | srv2 | Certificado del servidor, firmado por la CA |

Las claves privadas (`*.key`) y las capturas (`*.pcap`) no se incluyen en el repositorio.

---

## 🟥 Primera Parte · FTPS protegido por Firewall UFW

### Punto 1 · srv2 no es alcanzable directamente

srv1 es el único equipo con una interfaz en cada red, así que es el único camino entre el cliente y srv2. Además, srv2 tiene su propio UFW con política `deny` para lo entrante y solo acepta conexiones que vengan de 192.168.50.3 (srv1). Tampoco responde ping.

| Prueba | Resultado |
|---|:---:|
| `Test-NetConnection 192.168.50.2 -Port 21` antes del UFW de srv2 | `True` |
| La misma prueba con el UFW de srv2 activo | `False` |
| `ping 192.168.50.2` desde el cliente | 100% de pérdida |

### Punto 3 · `ufw allow` frente a `ufw route allow`

| Comando | Cadena | Controla |
|---|:---:|---|
| `ufw allow` | INPUT | Tráfico dirigido al propio firewall, como el SSH al puerto 22 de srv1 |
| `ufw route allow` | FORWARD | Tráfico que atraviesa el firewall hacia otra máquina, como el FTP hacia srv2 |

El DNAT cambia el destino a srv2 antes de decidir la ruta, así que el paquete nunca pasa por INPUT. Por eso `ufw allow 21` no serviría aquí. Sin la regla `ufw route allow` del puerto 21, el paquete cae en `deny (routed)` y la conexión da timeout. Al agregarla, la misma prueba pasa de `False` a `True`.

### Punto 4 · Propósito de cada regla

| Regla | Para qué sirve en FTPS |
|---|---|
| `deny (incoming)` y `deny (routed)` | Todo cerrado por defecto. Solo pasa lo permitido a mano |
| `22/tcp ALLOW IN` | Administrar srv1 por SSH |
| `21/tcp ALLOW FWD` | Deja cruzar el canal de control: login y comandos |
| `50000:50010/tcp ALLOW FWD` | Deja cruzar el canal de datos: listados y archivos |
| `DNAT dpt:21` | Lo que llega a 192.168.1.40:21 se entrega en srv2:21 |
| `DNAT dpts:50000:50010` | Lo mismo para los puertos de datos, conservando el puerto |
| `MASQUERADE` | srv2 le responde a srv1 y no al cliente, para que la respuesta vuelva por el firewall |

Las reglas NAT reescriben direcciones y las de filtrado autorizan el paso. Hacen falta las dos: el DNAT sin el `ufw route allow` manda el paquete hacia srv2 pero el firewall lo descarta.

### Punto 6 · Modo pasivo

| Pregunta | Respuesta |
|---|---|
| **(a)** ¿Por qué el rango debe coincidir con el firewall? | vsftpd abre un puerto entre 50000 y 50010 por cada listado o archivo. Si el firewall no reenvía y permite exactamente ese rango, el login funciona pero el listado se queda colgado |
| **(b)** ¿Por qué en FTPS el firewall no abre los puertos solo? | En FTP plano el firewall puede leer la respuesta `227` y abrir ese puerto al vuelo. En FTPS esa respuesta va cifrada, no la puede leer, y el rango se abre fijo y a mano |
| **(c)** ¿Qué pasa sin `pasv_address` detrás de NAT? | vsftpd anuncia su IP privada 192.168.50.2. El cliente intenta conectarse ahí, no llega, y el canal de datos falla |

### Punto 7 · Certificado en FileZilla

| Campo | Valor |
|---|---|
| Sujeto | `CN = srv2-2236320` |
| Emisor | `CN = CA-Parcial2-2236320` |
| Vigencia | 365 días desde la emisión |
| Huella SHA-256 | Igual a la de `openssl x509 -in servidor.crt -noout -fingerprint -sha256` |

El certificado no es autofirmado: lo firma una CA propia, por eso sujeto y emisor son distintos. Que la huella coincida confirma que FileZilla recibió el mismo certificado que está instalado en srv2, a través del reenvío.

### Punto 8 · Verificación con `openssl s_client`

| Dato | Resultado |
|---|---|
| Certificado | `CN = srv2-2236320` |
| Cadena de confianza | `Verify return code: 0 (ok)` |
| Versión de TLS | TLSv1.3 |
| Suite de cifrado | `TLS_AES_256_GCM_SHA384` |

El código es 0 porque el cliente recibe `ca.crt` con `-CAfile` y puede comprobar la firma de la CA sobre el certificado. Sin `-CAfile` el código es `21 (unable to verify the first certificate)`: el cliente no conoce a la CA que firmó y no tiene con qué validar.

### Punto 9 · FTP sin cifrar frente a FTPS

| | `ftp_plano.pcap` | `ftps.pcap` |
|---|---|---|
| Usuario y contraseña | Legibles: `USER ftpuser` y `PASS` | Cifrados |
| Contenido del archivo | Legible con el filtro `ftp-data` | `Application Data` |
| Canal de control | Todos los comandos en claro | `AUTH TLS`, `234` y handshake TLS en el puerto 21 |
| Canal de datos | En claro | Handshake TLS propio en cada puerto (50004 y 50005) |

---

## 🟦 Segunda Parte · DNS sobre TLS

### Punto 10 · `DNSOverTLS=yes` frente a `opportunistic`

| Valor | Comportamiento |
|---|---|
| `yes` | Estricto. Solo usa DoT y valida el certificado del servidor contra el nombre después del `#`. Si el puerto 853 no responde, la resolución falla |
| `opportunistic` | Intenta DoT y, si no puede, baja a DNS sin cifrar por el puerto 53 sin avisar. No valida el certificado, así que un atacante puede forzar esa bajada |

### Punto 11 · Dónde se evidencia DoT

En el bloque `Global` de `resolvectl status`: la línea `Protocols` muestra **`+DNSOverTLS`** (el `+` es encendido) y la línea `DNS Servers` muestra `1.1.1.1#cloudflare-dns.com 8.8.8.8#dns.google`.

### Punto 12 · Por qué `dig @8.8.8.8` no usa DoT

Los tres dominios (`uao.edu.co`, `github.com`, `wikipedia.org`) se resolvieron con `encrypted transport: yes`, y `dig` sin servidor mostró `SERVER: 127.0.0.53`. Con `@8.8.8.8`, dig le pregunta directo a Google por UDP 53 y se salta a systemd-resolved, que es el único que cifra. Esa consulta viaja en texto plano.

### Punto 13 · Qué queda expuesto sin cifrar

| | Con DoT (`tcp.port == 853`) | Sin DoT (`udp.port == 53`) |
|---|---|---|
| Dominio consultado | No se ve | `wikipedia.org` |
| Tipo de registro | No se ve | `A` y `AAAA` |
| Respuesta | No se ve | `208.80.154.224` |
| Lo que muestra Wireshark | `Client Hello`, `Server Hello`, `Application Data` | `Standard query A wikipedia.org` |

Sin cifrar, cualquiera en el camino lee qué sitio se va a visitar y puede alterar la respuesta.

### Punto 14 · Análisis

**Qué sigue visible con DoT:** la IP del resolver (1.1.1.1), el puerto 853, el nombre del servidor en el `Client Hello` (SNI `cloudflare-dns.com`), y el tamaño y momento de los paquetes. No se ve el dominio ni la respuesta.

| Si un firewall bloquea el 853 | Resultado |
|---|---|
| Con `yes` | La resolución falla. Seguro, pero sin servicio |
| Con `opportunistic` | Baja a DNS plano por el 53. Funciona, pero sin cifrar |

| | DoT | DoH |
|---|---|---|
| Puerto | TCP 853, propio | TCP 443, el de HTTPS |
| Se identifica como DNS | Sí, por el puerto | No, se confunde con tráfico web |
| Facilidad para bloquearlo | Alta: basta cerrar el 853 | Baja: habría que cerrar el 443 |

Como evidencia adicional se capturó una consulta DoH con `curl` hacia `https://1.1.1.1/dns-query`: en la captura solo aparece un handshake TLS y `Application Data` en el puerto 443, igual que cualquier visita a una página web.

---

## 🟩 Tercera Parte · SFTP protegido por Firewall UFW

### Punto 15 · Usuario exclusivo de SFTP

| Directiva | Qué hace |
|---|---|
| `Match User sftp_2236320` | Aplica las reglas solo a este usuario |
| `ChrootDirectory /home/sftp_2236320` | Lo encierra en su carpeta, que para él es la raíz |
| `ForceCommand internal-sftp` | Solo le da SFTP, aunque pida una terminal |

`sftp sftp_2236320@...` entra y lista la carpeta `archivos`. `ssh sftp_2236320@...` responde `This service allows sftp connections only.` y cierra la conexión.

### Punto 16 · Reenvío del puerto 2222

Se usa el 2222 porque el 22 de srv1 ya es el SSH de administración del firewall. El DNAT cambia IP y puerto (`192.168.1.40:2222` a `192.168.50.2:22`) antes del filtrado, por eso la regla `ufw route allow` dice `port 22`.

| Prueba | Resultado |
|---|---|
| `sftp -P 2222` sin la regla `ufw route` | `Connection timed out` |
| `sftp -P 2222` con la regla | Entra y muestra `sftp>` |
| `nc -zv 192.168.50.2 22` desde el cliente | `timed out` |

### Punto 17 · Huella de la clave de host

La huella mostrada al cliente en la primera conexión fue `SHA256:CifvuKnCFUxaTaHjJPvXJRQcfQVeROGRu5rhIY1FQYs`, igual a la de `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` en srv2. El cliente le habla a srv1, pero la huella es la de srv2: eso confirma que el reenvío funciona y que no hay nadie en medio. Se documentó `ls`, `put` y `get` sobre la carpeta `archivos`.

### Punto 18 · Comparación de las tres capturas

| Criterio | FTP plano | FTPS | SFTP |
|---|---|---|---|
| Conexiones TCP por sesión | 1 de control + 1 por operación | 1 de control + 1 por operación | **1 sola** |
| Puertos usados | 21 y 50000-50010 | 21, 50004 y 50005 | 2222 |
| Usuario y contraseña | Legibles | Cifrados | Cifrados |
| Contenido del archivo | Legible | Cifrado | Cifrado |
| Lo que queda en claro | Todo | Saludo `220`, `AUTH TLS` y handshake | Versión `SSH-2.0-OpenSSH_8.9p1` y algoritmos |
| Cuándo empieza el cifrado | Nunca | Después de `AUTH TLS` | Antes del login |

En `sftp.pcap` todos los paquetes usan el mismo par de puertos de principio a fin: login, listado, subida y descarga van por un único canal. Con FTPS un observador puede contar las transferencias por los puertos de datos; con SFTP solo sabe que hubo una conexión SSH.

### Punto 19 · FTPS frente a SFTP

| Criterio | FTPS | SFTP |
|---|---|---|
| Protocolo base | FTP con una capa TLS encima | SSH (subsistema sftp de OpenSSH) |
| Conexiones y puertos | Dos canales: control (21) y datos (un puerto entre 50000 y 50010 por transferencia) | Un solo canal y un solo puerto (22, publicado como 2222) |
| Autenticación del servidor | Certificado X.509 firmado por una CA, se valida la cadena de confianza | Clave de host SSH, se confía en la huella la primera vez |
| Momento en que inicia el cifrado | Después de `AUTH TLS`. El saludo y ese comando viajan en claro | Desde el intercambio de claves, antes de pedir usuario y contraseña |
| Atravesar firewall y NAT | Difícil: rango pasivo fijo, `pasv_address`, y el firewall no puede leer el canal de control | Fácil: un solo reenvío de puerto |
| Facilidad de configuración | Más pasos: CA, certificado, `vsftpd.conf` y 4 reglas en el firewall | Menos pasos: un bloque en `sshd_config` y 2 reglas en el firewall |

> [!IMPORTANT]
> **Conclusión.** Para un entorno con restricciones de firewall estrictas es más adecuado **SFTP**.
>
> En mis pruebas, FTPS necesitó abrir 12 puertos (el 21 y del 50000 al 50010), dos reglas DNAT, dos reglas `ufw route` y configurar `pasv_address`. Como el canal de control va cifrado, el firewall no puede leer la respuesta del modo pasivo y el rango tiene que quedar abierto de forma fija.
>
> SFTP funcionó con un solo puerto (2222), una regla DNAT y una regla `ufw route`. En la captura es una única conexión TCP donde lo único legible es la versión de SSH.
