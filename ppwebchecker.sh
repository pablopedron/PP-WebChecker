#!/usr/bin/env bash
# ==========================================================
#  PP-WebChecker - Auditoría rápida de seguridad de una web
#  Autor:   Pablo Pedrón
#  GitHub:  https://github.com/pablopedron
#  Versión: 1.0
#
#  Uso:     ./ppwebchecker.sh <url>
#  Ejemplo: ./ppwebchecker.sh https://miweb.com
#
#  Solo hace peticiones normales (GET/HEAD/OPTIONS): no explota nada.
#  Aun así, úsalo solo en webs tuyas o con permiso.
# ==========================================================

VERDE="\e[32m"; ROJO="\e[31m"; AMARILLO="\e[33m"; CIAN="\e[36m"
NEGRITA="\e[1m"; GRIS="\e[2m"; NORMAL="\e[0m"

ok()    { echo -e "  ${VERDE}[✓]${NORMAL} $*"; }
mal()   { echo -e "  ${ROJO}[✗]${NORMAL} $*"; }
aviso() { echo -e "  ${AMARILLO}[!]${NORMAL} $*"; }
info()  { echo -e "  ${CIAN}[*]${NORMAL} $*"; }
titulo(){ echo; echo -e "${NEGRITA}== $* ==${NORMAL}"; }

echo -e "${CIAN}"
cat <<'BANNER'
██████╗ ██████╗       ██╗    ██╗███████╗██████╗  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗
██╔══██╗██╔══██╗      ██║    ██║██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██████╔╝██████╔╝█████╗██║ █╗ ██║█████╗  ██████╔╝██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
██╔═══╝ ██╔═══╝ ╚════╝██║███╗██║██╔══╝  ██╔══██╗██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██║     ██║           ╚███╔███╔╝███████╗██████╔╝╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
╚═╝     ╚═╝            ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
BANNER
echo -e "${NORMAL}  by ${NEGRITA}Pablo Pedrón${NORMAL} · github.com/pablopedron"

# ---------------------------------------------------------- entrada
url=${1%/}   # quitamos la barra final si la tiene
if [ -z "$url" ]; then
  echo; mal "Falta la URL. Uso: $0 https://ejemplo.com"; exit 1
fi
[[ "$url" != http* ]] && url="https://$url"
command -v curl >/dev/null || { mal "Necesitas curl instalado"; exit 1; }

CURL=(curl -s -k --max-time 8 -A "PP-WebChecker/1.0")
cabeceras=$("${CURL[@]}" -I -L "$url" | tr -d '\r')
if [ -z "$cabeceras" ]; then
  echo; mal "No responde: $url"; exit 1
fi
# Si hubo redirecciones, nos quedamos con las cabeceras de la última respuesta
ultimas=$(awk '/^HTTP\//{b=""} {b=b $0 "\n"} END{printf "%s", b}' <<<"$cabeceras")
cab() { grep -i "^$1:" <<<"$ultimas" | head -1 | cut -d' ' -f2- ; }

puntos=0; total=0
suma() { total=$((total+1)); [ "$1" = 1 ] && puntos=$((puntos+1)); }

# ---------------------------------------------------------- 1. información
titulo "Información"
info "URL:      $url"
info "Estado:   $(head -1 <<<"$ultimas")"
[ -n "$(cab server)" ]        && aviso "Server:       $(cab server)  ${GRIS}(revela el software)${NORMAL}"
[ -n "$(cab x-powered-by)" ]  && aviso "X-Powered-By: $(cab x-powered-by)  ${GRIS}(revela la tecnología y su versión)${NORMAL}"
[ -n "$(cab x-generator)" ]   && aviso "X-Generator:  $(cab x-generator)"

# ¿HTTP redirige a HTTPS?
if [[ "$url" == https://* ]]; then
  destino=$("${CURL[@]}" -o /dev/null -w '%{redirect_url}' "http://${url#https://}")
  if [[ "$destino" == https://* ]]; then ok "HTTP redirige a HTTPS"; suma 1
  else mal "HTTP no redirige a HTTPS"; suma 0; fi
else
  mal "La web se sirve por HTTP, sin cifrar"; suma 0
fi

# ---------------------------------------------------------- 2. cabeceras de seguridad
titulo "Cabeceras de seguridad"
revisar() {  # $1 cabecera, $2 para qué sirve
  if [ -n "$(cab "$1")" ]; then ok "$1"; suma 1
  else mal "$1 ${GRIS}- falta: $2${NORMAL}"; suma 0; fi
}
revisar strict-transport-security "obliga a usar HTTPS (HSTS)"
revisar content-security-policy   "frena ataques XSS"
revisar x-frame-options           "evita clickjacking (meter tu web en un iframe)"
revisar x-content-type-options    "evita que el navegador adivine el tipo de fichero"
revisar referrer-policy           "controla qué URL se filtra a otras webs"
revisar permissions-policy        "limita cámara, micro, geolocalización..."

# ---------------------------------------------------------- 3. cookies
titulo "Cookies"
cookies=$(grep -i '^set-cookie:' <<<"$ultimas")
if [ -z "$cookies" ]; then
  info "La página principal no crea cookies"
else
  while read -r linea; do
    nombre=$(sed -E 's/^[^:]+: *([^=]+)=.*/\1/' <<<"$linea")
    falta=""
    grep -qi 'secure'   <<<"$linea" || falta+=" Secure"
    grep -qi 'httponly' <<<"$linea" || falta+=" HttpOnly"
    grep -qi 'samesite' <<<"$linea" || falta+=" SameSite"
    if [ -z "$falta" ]; then ok "Cookie $nombre bien configurada"; suma 1
    else mal "Cookie $nombre sin:$falta"; suma 0; fi
  done <<<"$cookies"
fi

# ---------------------------------------------------------- 4. ficheros expuestos
titulo "Ficheros sensibles expuestos"
# Muchas webs devuelven 200 para cualquier ruta (soft 404). Por eso, además del
# código, comprobamos que el contenido sea el que esperamos de cada fichero.
comprobar() {  # $1 ruta, $2 texto que debe contener, $3 descripción, $4 grave(1)/info(0)
  local cuerpo codigo
  cuerpo=$("${CURL[@]}" -w '\n%{http_code}' "$url$1")
  codigo=${cuerpo##*$'\n'}
  cuerpo=${cuerpo%$'\n'*}
  if [ "$codigo" = 200 ] && grep -qiE "$2" <<<"$cuerpo"; then
    if [ "$4" = 1 ]; then mal "$1 ${GRIS}- $3${NORMAL}"; suma 0
    else info "$1 ${GRIS}- $3${NORMAL}"; fi
    return 0
  fi
  return 1
}
encontrados=0
comprobar "/.git/HEAD"       "^ref: refs/"                 "repositorio Git expuesto: se puede descargar el código" 1 && encontrados=1
comprobar "/.env"            "^[A-Z_]+=|APP_KEY|DB_PASS"   "variables de entorno (contraseñas, claves de API)" 1 && encontrados=1
comprobar "/phpinfo.php"     "phpinfo\(\)|PHP Version"     "phpinfo() muestra toda la configuración del servidor" 1 && encontrados=1
comprobar "/info.php"        "phpinfo\(\)|PHP Version"     "phpinfo() muestra toda la configuración del servidor" 1 && encontrados=1
comprobar "/.DS_Store"       "Bud1"                        "fichero de macOS que lista el contenido de carpetas" 1 && encontrados=1
comprobar "/server-status"   "Apache Server Status"        "estado de Apache: IPs y peticiones en tiempo real" 1 && encontrados=1
comprobar "/composer.json"   "\"require\""                 "lista de dependencias PHP y sus versiones" 1 && encontrados=1
comprobar "/.htaccess"       "RewriteEngine|Deny|Allow"    "configuración interna de Apache" 1 && encontrados=1
comprobar "/backup.sql"      "INSERT INTO|CREATE TABLE"    "copia de la base de datos" 1 && encontrados=1
comprobar "/phpmyadmin/"     "<title>phpmyadmin|pma_username"                "panel de phpMyAdmin accesible" 1 && encontrados=1
comprobar "/wp-login.php"    "wordpress|wp-submit"         "es un WordPress (login por defecto)" 0
[ $encontrados = 0 ] && { ok "No se ha encontrado ninguno de los ficheros sensibles revisados"; suma 1; }

# robots.txt: no es un fallo, pero a veces señala rutas interesantes
robots=$("${CURL[@]}" -w '\n%{http_code}' "$url/robots.txt")
if [ "${robots##*$'\n'}" = 200 ] && grep -qi '^disallow' <<<"$robots"; then
  info "robots.txt oculta estas rutas (mira qué hay):"
  grep -i '^disallow:' <<<"$robots" | awk '{print $2}' | grep -v '^/$' | sort -u | head -10 | sed 's/^/        /'
fi

# ---------------------------------------------------------- 5. métodos HTTP
titulo "Métodos HTTP"
permitidos=$("${CURL[@]}" -X OPTIONS -I "$url" | tr -d '\r' | grep -i '^allow:' | cut -d' ' -f2-)
if [ -n "$permitidos" ]; then
  info "El servidor permite: $permitidos"
  if grep -qiE 'PUT|DELETE|TRACE' <<<"$permitidos"; then
    mal "Hay métodos peligrosos activados (PUT/DELETE/TRACE)"; suma 0
  else ok "Sin métodos peligrosos"; suma 1; fi
else
  info "El servidor no dice qué métodos permite"
fi

# ---------------------------------------------------------- resumen
titulo "Resultado"
nota=$(( puntos * 100 / total ))
if   [ $nota -ge 85 ]; then color=$VERDE;    letra=A
elif [ $nota -ge 70 ]; then color=$VERDE;    letra=B
elif [ $nota -ge 50 ]; then color=$AMARILLO; letra=C
elif [ $nota -ge 30 ]; then color=$ROJO;     letra=D
else                        color=$ROJO;     letra=F; fi
echo -e "  Nota: ${color}${NEGRITA}${letra}${NORMAL} (${puntos}/${total} comprobaciones superadas)"
echo
