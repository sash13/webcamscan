#!/bin/bash

# Загружаем настройки
. "$(dirname "$0")/wcs-config.sh"
export NMAPDIR="${NMAPDIR:-.}"
export WRITE_ALL_HOSTS="${WRITE_ALL_HOSTS:-true}"
export HOST_TIMELIMIT="${HOST_TIMELIMIT:-5m}"
export RTSP_URLS="${RTSP_URLS:-./rtsp-urls.txt}"
export FIND_AUTH="${FIND_AUTH:-true}"
export BRUTEFORCE="${BRUTEFORCE:-true}"
export BRUTEFORCE_TIMELIMIT="${BRUTEFORCE_TIMELIMIT:-2m}"
export LIBAV_LIMIT="${LIBAV_LIMIT:-4}"
export LIBAV_SCREENSHOT="${LIBAV_SCREENSHOT:-true}"
export SAVE_NO_FLAGS="${SAVE_NO_FLAGS:-false}"
export CLEANUP="${CLEANUP:-true}"

# 'Константные' регексы
export REGEX_IP='([0-9]{1,3}\.){3}[0-9]{1,3}'
export REGEX_URL_RSTP='rtsp://[0-9.]+/\S*'
#                1      1   2           23 4      43 5  5
export PCRE_URL='([a-z]+)://([a-z0-9.-]+)(:([0-9]+))?(.*)'


function wcs_print () {
	printf '%s' "$@" 1>&2
	return 0
}

function wcs_println () {
	printf '%s\n' "$@" 1>&2
	return 0
}

function wcs_printb () {
	printf '%b' "$@" 1>&2
	return 0
}

function wcs_error () {
	printf '%b' "$@" 1>&2
	exit 1
}


# Прогресс: $1 - позиция, $2 - максимум.
function wcs_echo_progress () {
	wcs_print " $(bc -l <<< "scale=1; 100.0*($1-0.5)/$2")%"
}

function wcs_echo_subprogress () {
	wcs_print '.'
}


function wcs_check_bash () {
	(( ${BASH_VERSION%%[^0-9]*} < 4 )) \
		&& wcs_error "Вы используете устревший ($BASH_VERSION) bash, не обходима версия не ниже 4."
	return 0
}

function wcs_check_root () {
	[[ $EUID -ne 0 ]] \
		&& wcs_error "Скрипт должен работать от root."
	return 0
}

function wcs_check_pcregrep () {
	pcregrep --version &> /dev/null \
		|| wcs_error "pcregrep не обнаружен."
	return 0
}

function wcs_check_nmap () {
	nmap --version &> /dev/null \
		|| wcs_error "nmap не обнаружен."
	return 0
}

function wcs_check_file () {
	[[ "$1" != '-' && ! -f "$1" ]] \
		&& wcs_error "Файл '$1' не найден!"
	return 0
}

function wcs_alloc_temp () {
	mktemp
	return 0
}


# Исправляет владельца файла из-за выполенния от root'а:
# $1 - файл, stdio - игнорируется
function wcs_fix_own () {
	if [[ -n "$1" && -e "$1" ]]
	then
		# Не уверен, что это правильно.
		local u=$(who am i | awk '{print $1}')
		chown -R "$u:$u" "$1" &> /dev/null
	fi
	return 0
}


# Обход по файлу с прогрессом:
# $1 - файл, $2... - коллбек, stderr - сообщения wcs
function wcs_iterate_file () {
	local file="$1"
	shift
	local n=$(( $(wc -l < "$file") + 1 ))
	local i=1
	while IFS=$'\n' read -r item || [[ -n "$item" ]]
	do
		wcs_echo_progress "$(( i++ ))" "$n"
		$@ "$item" #INVOKE CALLBACK
	done < "$file"
	wcs_println # NL после прогресса
	return 0
}

# Обход по stdin с прогрессом:
# $1... - коллбек, stderr - сообщения wcs
function wcs_iterate_stdin () {
	local i=1
	local item
	while IFS=$'\n' read -r item || [[ -n "$item" ]]
	do
		wcs_print " $(( i++ ))"
		$@ "$item" #INVOKE CALLBACK
	done
	wcs_println # NL после прогресса
	return 0
}


# Первичное сканирование целей: 
# $1 - цели, stdout - найденые, stderr - чист
function wcs_discover_nmap () {
	nmap --privileged -n -sS -sU -p T:554,U:554 --open --max-retries 3 --host-timeout 10s \
		--randomize-hosts --min-parallelism=4 --min-hostgroup=4096 --max-hostgroup=65536 \
		-oG - $(printf "%q" "$1" ) 2>&1 | grep 'open/' | grep -Eo "$REGEX_IP" | uniq 2>/dev/null
		#     ^ этот костыль нужен, потому что nmap не принимает список хостов
		#       как один аргумент, но переменные нужно как-то экранировать.
	return 0
}

# Первичное сканирование целей:
# $1 или stdin - цели, stdout - найденые, stderr - сообщения wcs
function wcs_discover_stdout () {
	if [[ -z "$1" || "$1" == '-' ]]
	then
		wcs_iterate_stdin wcs_discover_nmap | sort -R - | uniq
	else
		wcs_iterate_file "$1" wcs_discover_nmap | sort -R - | uniq
	fi
	return 0
}

# Первичное сканирование целей:
# $1 или stdin  - цели , $2 или stdout - найденые, stderr - сообщения wcs
function wcs_discover () {
	if [[ -z "$2" || "$2" == '-' ]]
	then
		wcs_discover_stdout "$1"
	else
		wcs_discover_stdout "$1" >> "$2"
		wcs_fix_own "$2"
	fi
	return 0
}


# Снимает пробу:
# $1 - URL трансляции, stdout - лог пробы, stderr - сообщения wcs
function wcs_libav_probe () {
	timeout -k 5 25 avprobe -v info "$1" 2>&1 \
		&& wcs_println "Не удаётся сделать avprobe '$1'!"
	return 0
}

# Сохраняет скриншот:
# $1 - трансляция, $2 - файл, stdout - лог, stderr - сообщения wcs
function wcs_libav_screenshot () {
	timeout -k 5 25 avconv -v quiet -i "$1" -ss 3 -qscale 0 -t 1 -r 1 "$2" 2>&1
	[[ -f "$2" ]] && wcs_fix_own "$2" \
		&& wcs_println "Скриншот '$1' сохранен в '$2'." || wcs_println "Не удаётся сделать скриншот '$1'!"
	return 0
}

# Глубокое сканирование хоста:
# $1 - папка, $2 - хост, stdout - игнорируется, stderr - сообщения wcs
function wcs_deep_scan_host () {
	if [[ "$WRITE_ALL_HOSTS" = 'true' ]]
	then
		local file="${1}/all_hosts.txt"
		echo "$2" >> "$file"
		wcs_fix_own "$file"
	fi

	local script='rtsp-methods,rtsp-url-brute,http-title'
	[[ "$FIND_AUTH" = 'true' ]] && script="$script,http-auth,http-auth-finder"
	[[ "$BRUTEFORCE" = 'true' ]] && script="$script,http-brute,http-form-brute"

	local script_args="unpwdb.timelimit='$BRUTEFORCE_TIMELIMIT'"
	script_args="$script_args,rtsp-url-brute.urlfile='$RTSP_URLS',brute.retries=10240"
	script_args="$script_args,http-auth.path='/',http-form-brute.path='/',http-brute.path='/'"

	local nmap_tmp=$(wcs_alloc_temp)

	# 81,8008,8081 - Beward MJPG
	nmap -vvv --privileged -T4 -n -PN -sS -sU -p T:80,T:81,T:8008,T:8080,T:8081,T:554,U:554 --reason \
		--script "$script" --script-args "$script_args" \
		--host-timeout "$HOST_TIMELIMIT" "$2" &> "$nmap_tmp"

	local f=''

	# Флаг: Ошибка
	grep -q 'Skipping host [0-9.]+ due to host timeout' "$nmap_tmp" \
		&& f="${f}_timeout"

	# Флаг: Есть рабочая HTTP-служба
	grep -qE '[0-9]+/tcp\s+open\s+https?' "$nmap_tmp" \
		&& f="${f}_http" 

	# Флаг: Найден логин-пароль
	grep -q 'Valid credentials' "$nmap_tmp" \
		&& f="${f}_creds" 

	 # Флаг: Не найден логин-пароль
	grep -q 'No valid accounts found' "$nmap_tmp" \
		&& f="${f}_nocreds"

	# Флаг: Есть рабочая  RTSP-служба
	grep -qz 'rtsp-methods:.*DESCRIBE' "$nmap_tmp" \
		&& f="${f}_rtsp" 

	# Флаг: Ошибка
	grep -q 'An error occured while testing the following URLs' "$nmap_tmp" \
		&& f="${f}_error" # Флаг: Ошибка

	# Флаг: Есть рабочие стримы
	if grep -q 'Discovered URLs' "$nmap_tmp"
	then
		f="${f}_found" 

		local libav_tmp=$(wcs_alloc_temp)

		local i=0
		grep -Eo "$REGEX_URL_RSTP" "$nmap_tmp" | \
		while IFS=$'\n' read -r item3 || [[ -n "$item3" ]]
		do
			if [ "$(( i++ ))" -ge "$LIBAV_LIMIT" ]
			then
				wcs_println "Достигнут LIBAV_LIMIT ($LIBAV_LIMIT)!" &>> "$libav_tmp"
				break
			fi
			wcs_echo_subprogress
			wcs_libav_probe "$item3" &>> "$libav_tmp"
			[[ "$LIBAV_SCREENSHOT" = 'true' ]] \
				&& wcs_libav_screenshot "$item3" "${1}/${2}_${i}.jpg" &>> "$libav_tmp"
			wcs_printb '\n' &>> "$libav_tmp" # Разделительная пустая строка.
		done
		wcs_printb '\n\n' &>> "$libav_tmp" # Разделительная пустая строка.

		# Флаг: Есть видео
		grep -q 'Stream #[.0-9]*: Video' "$libav_tmp" \
			&& f="${f}_video"

		# Флаг: Есть звук
		grep -q 'Stream #[.0-9]*: Audio' "$libav_tmp" \
			&& f="${f}_audio"

		# Флаг: TCP
		grep -q 'Interleaved RTP mode is not supported yet' "$libav_tmp" \
			&& f="${f}_il"

		cat "$libav_tmp" >> "$nmap_tmp"

		wcs_clean "$libav_tmp"
	fi

	local out_all="${1}/all.txt"
	if [[ -n "$f" || "$SAVE_NO_FLAGS" = 'true' ]]
	then
		cat "$nmap_tmp" >> "$out_all" # ! Дозапись
		local infofile="${1}/${2}${f}_.txt"
		cat "$nmap_tmp" >> "$infofile" # ! Дозапись
		wcs_fix_own "$infofile"
	else
		wcs_printb "\nПропуск '$2': Нет тегов.\n\n" &>> "$out_all" # ! Дозапись
	fi

	wcs_clean "$nmap_tmp"
}

function wcs_deep_scan () {
	mkdir -p "$2" &> /devnull
	[[ -d "$2" ]] || wcs_error "Не удаётся создать папку '$2'."
	if [[ -z "$1" || "$1" == '-' ]]
	then
		wcs_iterate_stdin wcs_deep_scan_host "$2"
	else
		wcs_iterate_file "$1" wcs_deep_scan_host "$2"
	fi
	wcs_fix_own "$2"
	return 0
}


function wcs_clean () {
	if [[ -e "$1"  ]]
	then
		if [[ "$CLEANUP" = 'true' ]] 
		then
			rm -rf "$1"
		else
			wcs_fix_own "$2"
		fi
	fi
}

