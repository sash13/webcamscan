# webcamscan
Скрипт для полу-автоматического поиска веб-камер в сети, умеющий искать RTSP-трансляции и делать их срины, умеющий подбирать логин-пароли для вэб-панелей, умеющий сортировать результаты и ставить тэги.

___
**ВНИМАНИЕ: Скрипт предназначен только для ознакомительных и учебных целей. Использование его может быть *противозаконным*. Используйте его на свой страх и риск с согласия всех участников.**
___

### Зависимости скрипта:
Обязательно:
* ~~ЖМУ/Пинус~~ GNU/Linux. Может быть и OSX, но я не пробовал.
* `bash`, ну или какой-нибудь еще шелл.
* Команда `timeout`, сейчас она есть везде, но вдруг вы — аутист?
* `nmap-nse` — NMap с поддержкой скриптов (NSE).
* `libav` (`avprobe`, `avconv`) — Для анализа трансляций и скриншотов.

Не обязательно:
* `git`, что бы склонировать реп.
* TODO: `ffmpeg` (`ffprobe`) как альтернатива `libav`.

### Запуск скрипта:
* `git clone https://github.com/voaoom/webcamscan.git`
* `cd webcamscan`
* `chmod +x ./webcamscan.sh`
* Вы можете поднастроить скрипт по своему вкусу, раскомментировав и поправив в строки в файле `./config.sh`. См. ниже.
* Скрипт работает под правами суперпользователя. Это необходимо для эффективной работы `nmap`. Где гарантии, что он не сделает `rm -rf /`? Их нет, мне похуй.
* Скрипт принимает на вход файл с подсетями-целми: `sudo ./webcamscan.sh <путь/к/списку/адресов.txt>`. Список адресов содержит либо конкретные хосты и адреса, либо подсети, разделенные любыми проблеьными символами.

### Настройки скрипта
Вы можете поднастроить скрипт по своему вкусу, раскомментировав и поправив в строки в файле `./config.sh`. Будте осторожны: я не делал защиту от дебилов. Неправильные значения могут поломать скрипт и снести вашу систему. **Почитайте ниже, как скрипт работает**, что бы понимать, что  происходит.
Параметры:
* `ПАРАМЕТР=значение-по-умолчанию` — описание. Булевые значения должны быть `true` или `false`.
* `NMAPDIR=.` — используется для указания `nmap`, где он работает.
* `WRITE_ALL_HOSTS=true` — записывать все обнаруженные адреса в файл all_hosts.txt или нет.
* `HOST_TIMELIMIT=5m` — cуммарное максимальное время затрачиваемое на один хост. Суффикс `m` означает минуты, еще можно `s` и `h` — секунды и часы. Не стоит выставлять большие значения. Скрипт не работает параллельно, так что во время тупления над одним хостом другие хосты не сканируются.
* `RTSP_URLS='./rtsp-urls.txt'` — Файл с возможными URL-ами RTSP, используется для перебора. Буду очень рад, если вы поможете мне его пополнить. За основу взят стандартный файл из `nmap`.
* `FIND_AUTH=true` — искать на хосте страницы с авторизацией или нет.
* `BRUTEFORCE=true` — делать ли перебор логин-паролей для вэб-панели, если это возможно или нет.
* `BRUTEFORCE_TIMELIMIT=1m` — максимальное время перебора логин-паролей на одном хосте. Здесь всё тоже, что и `HOST_TIMELIMIT`. Этого мало для серьёзного перебора, но находит всякие дурацкие пароли.
* `LIBAV_LIMIT=4` — Ограничение на анализ трансляций (из всех обнаруженных на одной камере). Это важное ограничение, ибо некоторые можели вэб-камер начисто игнорят URL-ы, и транслируют всегда. В таком случае `nmap` найдет чуть более, чем дохуя трансляций, но на самом деле это всё будет одна и таже. Да и вообще у многих камер есть параллельные трансляции. Что бы не тратить время на анализ потоков и нарезане скриншотов, нужно это ограничение.
* `LIBAV_SCREENSHOT=true` — пытаться делать скриншоты или нет.
* `SAVE_NO_FLAGS=false` — сохранять информацию о хостах, у которых нет тегов или нет.
* `CLEANUP=true` — удалять за собой временные файлы или нет.

### Работа скрипта:
* **Первый этап**: Скрипт, используя `nmap`, полностью сканирует все эти сети на предмет открытого RTSP-порта — это с 95% вероятностью вэб-камера (1% — медиасервер, 4% — что-нибудь еще). Все обнаруженные хосты сохраняются.
    * Примечание: Этот этап может выполняться долго и тихо, так что я добавил сюда прогресс. Прогресс отчитывается по строкам входного файла. Каждая строка по очереди загоняется в `nmap`, так что если всё будет записано в одну строку, то прогресса не будет, а если каждый адрес на своей строке, то на каждый адрес каждый раз будет завново запускаться `nmap`. Таким образом, первый случай быстрый, но не наглядный, а второй наглядный, но медленный.
* **Второй этап**: Скрипт, используя `nmap`, подробно сканирует найденые хосты. На этом этапе, в звисимости от настроек, происходит:
    * Быстрый **перебор логин-паролей** на HTTP-панели, если такая панель обнаружена, что бы найти пары типа `admin:admin` и `root:123456`.
    * Поиск других страниц авторизации, если они существуют, но они **пока** не перебираются. Перебираются только те, что находятся в `/` HTTP-службы.
    * Быстрый **перебор известных RTSP-URL-ов**, что бы найти все возможные трансляции, но нет гарантий, что скрипт точно обнаружит их. Если он не нашел ниодной трансляции, но RTSP-сервер выглядит рабочим, то, скорее всего, там используются более хитрые URL-ы и/или авторизация. Попробуйте порыться в вэб-панели, может найдете информацию. Если ничего не получилось, то этот хост можно прогнорировать или до-взламывать вручную.
    * Найденые RTSP-URL-ы передаются в `avprobe` для изучения трансляции, а также создаются их скриншоты с помощью `avconv`. Иногда сервера ебут мозги отправляя пустые пакеты или какой-нибудь мусор, из-за чего эти две программы начинают тупить и это может растянуться на часы. На них выставлено ограничение в несколько десятков секунд, так что есть вероятность, что они не выдадут результат.
    * Выхлоп программ парсится, на основе чего для каждого хоста **выставляются тэги**:
        * `http` — если была обнаружена хотя бы одна работающая HTTP-служба. От этого тэга зависят:
            * `creds` — если был обнаружен какой-то метод авторизации, был проведен перебор и он оказался успешным — учётные данные **найдены**.
            * `nocreds` — если был обнаружен какой-то метод авторизации, был проведен перебор и он оказался проавльным — учётные данные **не найдены**.
        * `rtsp` — если была обнаружена хотя бы одна RTSP-служба. От этого тэга зависят:
            * `found` — если найден хотя бы один корректный URL трансляции (но не гарантируется, что в трансляции корректные данные). 
            * `video` — если найдена хотя бы одна трансляция, содержащая **видео**-поток (но не гарантируется, что в этом потоке адекватные данные).
            * `audio` — если найдена хотя бы одна трансляция, содержащая **аудио**-поток (но не гарантируется, что в этом потоке адекватные данные).
            * `il` — почему-то `libav` не всегда дружит с Interleaved (TCP) RTSP. Если найдена хотя бы одна такая трансляция, то выставляется этот тэг. Это **не** означает, что трансляция не работает. Она, вероятно, будет открываться с ошибками в плеерах на основе `libav`, но может корректно работать в других, например `vlc`.
        * `error` — какая-то ошибка, из-за которой невозможно утверждать о корректности **отрицательных** результатов. Регистрируется в следующих случаях:
            * Скрипт `rtsp-url-brute` в `nmap` выкинул ошибку. Как правило, возникает, если нарушается протокол. Возможно, RTPS-служба, на самом деле не RTPS или просто она кривая и багнутая.
        * Если ниодин тэг не был проставлен, значит этот хост по-видимому не представляет интереса. Таких хостов может быть очень много.
        * Если зависимость тэгов нарушена, то отпишите мне. Не то что бы это был баг или типа того, ~~бака~~, возможно, этот новый неисследованый случай.
    * Результаты сохраняются:
        * В файлы вида `<папка-выхлопа>/<адрес-хоста>_[тэг_[...]].txt` — отчёт `nmap` и отчёты `avprobe`.
        * В файлы вида `<папка-выхлопа>/<адрес-хоста>_<порядковый-номер-трансляции>.jpg` — скриншот, сделаный `avconv`.
        * В файл `all_hosts.txt` — список всех адресов, которые сканировались на втором этапе.
        * В файл `all.txt` — все отчёты `nmap` и `avprobe` в хронологическом порядке.
        * По умолчанию `<пака-выхлопа>/` это `<путь-входного-файла>-webcam/`.
        * Если файлы уже существуют, то будет выполнена дозапись в их конец.
        * Сохранение происходит во время второго этапа, так что эти файлы будут появляться по мере обработки хостов.
