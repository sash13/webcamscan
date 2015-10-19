# webcamscan
Набор скриптов для полу-автоматического поиска веб-камер в сети, умеющий искать RTSP-трансляции и делать их срины, умеющий подбирать логин-пароли для вэб-панелей, умеющий сортировать результаты и ставить тэги.
Получается примерно так:
![Пример результата](http://i.imgur.com/SQy7fyo.png)

___
:bangbang: 

**ВНИМАНИЕ: Скрипт предназначен только для ознакомительных и учебных целей. Использование его может быть *противозаконным*. Используйте его на свой страх и риск с согласия всех участников.**

:bangbang: 
___

<a name="requestments"></a>
### Зависимости скрипта:

##### Обязательно:
* ~~ЖМУ/Пинус~~ GNU/Linux. Может быть и OSX, но я не пробовал.
* `bash` не ниже v.4.
* Команда `timeout`, сейчас она есть везде, но вдруг вы — аутист?
* `pcregrep` — grep с поддержкой PCRE.
* `nmap-nse` — NMap с поддержкой скриптов (NSE).
* `libav` (`avprobe`, `avconv`) — Для анализа трансляций и скриншотов.

##### Не обязательно:
* `git`, что бы склонировать реп.
* TODO: `ffmpeg` (`ffprobe`) как альтернатива `libav`.

<a name="launching"></a>
### Запуск скриптов

* `git clone https://github.com/voaoom/webcamscan.git`
* `cd webcamscan`
* `chmod +x ./wcs-*.sh`
* Вы можете поднастроить скрипт по своему вкусу, cм. ниже.
* Скрипты работают под правами суперпользователя. Это необходимо для эффективной работы `nmap`. Где гарантии, что он не сделает `rm -rf /`? Их нет, мне похуй.

<a name="wcs-config"></a>
### wcs-config.sh — Настройки скриптов

Вы можете поднастроить скрипт по своему вкусу, раскомментировав и поправив в строки в файле `./wcs-config.sh`, либо же установив переменные окружения перед запуском скриптов. Будте осторожны: я не делал защиту от дебилов. Неправильные значения могут поломать скрипты и снести вашу систему. **Почитайте ниже, как скрипты работает**, что бы понимать, что  происходит.
Описание параметров:
* `ПАРАМЕТР=значение-по-умолчанию` — описание. Булевые значения должны быть `true` или `false`.
* `NMAPDIR=.` — используется для указания `nmap`, где он работает.
* `PROGRESS=dynamic` — режим отображения прогресса:
    * `dynamic` — происходит обновление строки новыми значениями, видно только текущее состояние.
    * `static` — происходит дозапись новых значений после старых, видна история состояний.
    * `none` — прогресс не отображается.
* `WRITE_ALL_HOSTS=true` — записывать все обнаруженные адреса в файл all_hosts.txt или нет.
* `HOST_TIMELIMIT=5m` — cуммарное максимальное время затрачиваемое на один хост. Суффикс `m` означает минуты, еще можно `s` и `h` — секунды и часы. Не стоит выставлять большие значения. Скрипт не работает параллельно, так что во время тупления над одним хостом другие хосты не сканируются.
* `RTSP_URLS='./rtsp-urls.txt'` — Файл с возможными URL-ами RTSP, используется для перебора. Буду очень рад, если вы поможете мне его пополнить. За основу взят стандартный файл из `nmap`.
* `FIND_AUTH=true` — искать на хосте страницы с авторизацией или нет.
* `BRUTEFORCE=true` — делать ли перебор логин-паролей для вэб-панели, если это возможно или нет.
* `BRUTEFORCE_TIMELIMIT=2m` — максимальное время перебора логин-паролей на одном хосте. Здесь всё тоже, что и `HOST_TIMELIMIT`. Этого мало для серьёзного перебора, но находит всякие дурацкие пароли.
* `LIBAV_LIMIT=4` — Ограничение на анализ трансляций (из всех обнаруженных на одной камере). Это важное ограничение, ибо некоторые можели вэб-камер начисто игнорят URL-ы, и транслируют всегда. В таком случае `nmap` найдет чуть более, чем дохуя трансляций, но на самом деле это всё будет одна и таже. Да и вообще у многих камер есть параллельные трансляции. Что бы не тратить время на анализ потоков и нарезане скриншотов, нужно это ограничение.
* `LIBAV_SCREENSHOT=true` — пытаться делать скриншоты или нет.
* `SAVE_NO_FLAGS=false` — сохранять информацию о хостах, у которых нет тегов или нет.
* `CLEANUP=true` — удалять за собой временные файлы или нет.

<a name="wcs-discover"></a>
### wcs-discover.sh — Первичный поиск

Этот скрипт осуществляет поиск хостов, которые могут быть вэб-камерами с большой вероятностю, но не исследует их. По-сути этот скрипт из тысяч адресов выбирает те еденицы, которые имеет смысл сканировать. Он, используя `nmap`, полностью сканирует все указанные сети на предмет открытого RTSP-порта — это с 95% вероятностью вэб-камера (1% — медиасервер, 4% — что-нибудь еще). Все обнаруженные хосты сохраняются.

:information_source: **Примечание:** Этот скрипт может выполняться долго и тихо, так что я добавил сюда прогресс. Прогресс отчитывается по строкам входного файла. Каждая строка по очереди загоняется в `nmap`, так что если всё будет записано в одну строку, то прогресса не будет, а если каждый адрес на своей строке, то на каждый адрес каждый раз будет завново запускаться `nmap`. Таким образом, первый случай быстрый, но не наглядный, а второй наглядный, но медленный. При работе с файлами происходит подсчет строк и вывод осуществляется в процентах, но при чтении с `stdin` это не возможно, тогда прогресс просто подсчитывается возрастающими числами.

:computer: **Синтаксис:** `./wcs-discover.sh <файл-с-целями> <файл-с-обнаруженными-хостами>`. Можно указать `-`, это означает чтение из `stdin` и запись в `stdout`. Прогресс и сообщения пользователю выводятся в `stderr` в любом случае.

<a name="wcs-deepscan"></a>
### wcs-deepscan.sh — Глубокое сканирование

Этот скрипт, используя `nmap`, подробно сканирует найденые хосты. В звисимости от настроек, происходит:
* Быстрый **перебор логин-паролей** на HTTP-панели, если такая панель обнаружена, что бы найти пары типа `admin:admin` и `root:123456`.
* Поиск других страниц авторизации, если они существуют, но они **пока** не перебираются. Перебираются только те, что находятся в `/` HTTP-службы.
* Быстрый **перебор известных RTSP-URL-ов**, что бы найти все возможные трансляции, но нет гарантий, что скрипт точно обнаружит их. Если он не нашел ниодной трансляции, но RTSP-сервер выглядит рабочим, то, скорее всего, там используются более хитрые URL-ы и/или авторизация. Попробуйте порыться в вэб-панели, может найдете информацию. Если ничего не получилось, то этот хост можно прогнорировать или до-взламывать вручную.
* Найденые RTSP-URL-ы передаются в `avprobe` для **изучения трансляции**, а также **создаются** их **скриншоты** с помощью `avconv`. Иногда сервера ебут мозги отправляя пустые пакеты или какой-нибудь мусор, из-за чего эти две программы начинают тупить и это может растянуться на часы. На них выставлено ограничение в несколько десятков секунд, так что есть вероятность, что они не выдадут результат.
* Выхлоп программ парсится, на основе чего для каждого хоста **выставляются тэги**:
    * :page_facing_up: `http` — если была обнаружена хотя бы одна **работающая HTTP-служба**. От этого тэга зависят:
        * :unlock: `creds` — если был обнаружен какой-то метод авторизации, был проведен перебор и он оказался успешным — учётные данные **найдены**.
        * :lock: `nocreds` — если был обнаружен какой-то метод авторизации, был проведен перебор и он оказался проавльным — учётные данные **не найдены**.
    * :tv: `rtsp` — если была обнаружена хотя бы одна RTSP-служба. От этого тэга зависят:
        * :mag: `found` — если найден хотя бы один корректный **URL трансляции** (но не гарантируется, что в трансляции осмысленные данные). 
        * :camera: `video` — если найдена хотя бы одна трансляция, содержащая **видео**-поток (но не гарантируется, что в этом потоке осмысленные данные).
        * :sound: `audio` — если найдена хотя бы одна трансляция, содержащая **аудио**-поток (но не гарантируется, что в этом потоке осмысленные данные).
        * `il` — почему-то `libav` не всегда дружит с **Interleaved** (TCP) RTSP. Если найдена хотя бы одна такая трансляция, то выставляется этот тэг. Это **не** означает, что трансляция не работает. Она, вероятно, будет открываться с ошибками в плеерах на основе `libav`, но может корректно работать в других, например `vlc`.
    * :x: `error` — какая-то ошибка, из-за которой невозможно утверждать о корректности **отрицательных** результатов. Регистрируется в следующих случаях:
        * Скрипт `rtsp-url-brute` в `nmap` выкинул ошибку. Как правило, возникает, если нарушается протокол. Возможно, RTPS-служба, на самом деле не RTPS или просто она кривая и багнутая.
    * Если ниодин тэг не был проставлен, значит этот хост по-видимому не представляет интереса. Таких хостов может быть очень много.
    * Если зависимость тэгов нарушена, то отпишите мне. Не то что бы это был баг или типа того, ~~бака~~, возможно, этот новый неисследованый случай.
* Результаты сохраняются:
    * В файлы вида `<папка-выхлопа>/<адрес-хоста>_[тэг_[...]].txt` — отчёт `nmap` и отчёты `avprobe`.
    * В файлы вида `<папка-выхлопа>/<адрес-хоста>_<порядковый-номер-трансляции>.jpg` — скриншот, сделаный `avconv`.
    * В файл `<пака-выхлопа>/all_hosts.txt` — список всех адресов, которые сканировались на втором этапе.
    * В файл `<пака-выхлопа>/all.txt` — все отчёты `nmap` и `avprobe` в хронологическом порядке.
    * Если файлы уже существуют, то будет выполнена дозапись в их конец.

:information_source: **Примечание:** Этот скрипт может выполняться долго и тихо, так что я добавил сюда прогресс. Прогресс отчитывается по хостам на входе. Каждый хост по очереди обрабатывается, о чем сообщается в прогрессе. Если задействуется `libav`, то появляется под-прогресс в виде точек (`.`). При работе с файлами происходит подсчет строк и вывод осуществляется в процентах, но при чтении с `stdin` это не возможно, тогда прогресс просто подсчитывается возрастающими числами.

:computer: **Синтаксис:** `./wcs-deepscan.sh <файл-с-целями> <папка-выхлопа>`. В первом аргументе можно указать `-`, это означает чтение из `stdin`. Прогресс и сообщения пользователю выводятся в `stderr` в любом случае.

<a name="wcs-full"></a>
### wcs-full.sh — Глубокое сканирование

Этот скрипт по сути эквивалентен `./wcs-discover.sh <файл-с-целями> - | ./wcs-deepscan.sh - <папка-выхлопа>`, но скрипты исполняются **не** параллельно, а последовательно. Между их выполнением, все адреса собираются во временный буфер.

:computer: **Синтаксис:** `./wcs-full.sh <файл-с-целями> <папка-выхлопа>`.

<a name="wcs-brute"></a>
### wcs-brute.sh — Подбор логин-паролей

Этот скрипт помогает подобрать логин-пароли для служб цели. Поддерживаются протоколы: `http`, `https`, `ftp`. Если порт не указан, то используются `80`, `443` и `21` соответственно. Т.е. можно просто скопировать URL из браузера и всё. Вывод не управляется: `stdout` и `stderr` под контролем `nmap`.

:computer: **Синтаксис:** `./wcs-brute.sh <протокол>://<адрес>[:порт][/путь]`. 

<a name="wcs-lib"></a>
### wcs-lib.sh — Библиотека

Для внутреннего использования. Вам не следует трогать это.

<a name="bugs"></a>
### Известные баги
* Может выставиться тег `found`, но не выставиться `rtsp` — особенность скрипта `rtsp-methods` в `nmap`.

<a name="history"></a>
### История версий

( https://github.com/voaoom/webcamscan/releases )

**v3.2** — 2015-10-19
* Исправлена неработоспособность `./wcs-brute.sh`.

**v3.1** — 2015-10-19
* [Улучшен прогресс](https://github.com/voaoom/webcamscan/pull/2).

**v3** — 2015-10-18
* Теперь необходим `bash` v.4 и `pcregrep`.
* Скрипт разделен на несколько скриптов: `./wcs-discover.sh`, `./wcs-deepscan.sh` и `./wcs-full.sh`.
* Добавлен: `./wcs-brute.sh`.
* Добавлена поддержка `stdin` и `stdout` — можно использовать [в конвеерах](https://ru.wikipedia.org/wiki/%D0%9A%D0%BE%D0%BD%D0%B2%D0%B5%D0%B9%D0%B5%D1%80_(UNIX)).

**v2** — 2015-10-14
* Переписано на функциях, более структурированный и оптимизированный код.
* Изменения тегов:
    * `tcp` переименован в `il`.
    * `rtsp` переименован в `found`.
    * Добавлен (другой) `rtsp`.
* Добавлен параметр `SAVE_NO_FLAGS`.
* Параметр `BRUTEFORCE_TIMELIMIT` по умолчанию изменен с `1m` до `2m` + внутринние изменения о таймаутах.
* Добавлены записи в `rtsp-urls.txt` для видеорегистораторов RVi.

**v1** — 2015-10-13
* Первый релиз.