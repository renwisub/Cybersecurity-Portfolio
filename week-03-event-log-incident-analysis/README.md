# Windows Event Log Analysis: From Process Trees to Full Incident Reconstruction

## Задача

Серия из пяти растущих по сложности сценариев на разбор Windows Security Event Log: от единичного
подозрительного процесса до полного multi-stage инцидента с privilege escalation и exfiltration
данных. Цель — научиться отличать нормальную активность от атаки по цепочке Event ID, а не по
отдельным событиям в изоляции.

## Что искал

- `Event 4688` — создание процессов, включая LOLBins-паттерны (`cmd.exe → powershell.exe` с флагами `-enc`, `-Nop`, `-ExecutionPolicy Bypass`)
- `Event 4768/4769` — аномальные всплески Kerberos TGS-запросов (Kerberoasting)
- `Event 4720/4724/4728` — создание аккаунтов, смена паролей, добавление в привилегированные группы
- `Event 4624/4625` — успешные/неуспешные логоны, гео- и time-аномалии
- `Event 5156` — исходящие firewall-соединения как индикатор C2/exfiltration

## Процесс

**Сценарий 1 — Process tree analysis.** Из трёх событий `Event 4688` определил, какие два —
нормальная пользовательская активность (notepad, calc), а какое — атака: цепочка
`svchost.exe → cmd.exe → powershell.exe -Nop -ExecutionPolicy Bypass -c IEX(...)`. Флаг
`ExecutionPolicy Bypass` отключает встроенную защиту PowerShell, `IEX` выполняет произвольный
код — классический паттерн Living off the Land (LotL).

**Сценарий 2 — Kerberoasting alert triage.** Алёрт: 150 запросов `Event 4769` к сервису `SQL$`
за 5 минут от одного пользователя. Определил тип атаки, восстановил логику атакующего
(запрос TGS-билета → offline brute-force расшифровки → доступ к сервису) и расписал приоритет
действий: изоляция хоста → сброс паролей → сбор аргументов командной строки для forensics.

**Сценарий 3 — Backdoor + Privilege Escalation chain.** Связал пять разрозненных событий
(4720 → 4728 → 4624 → 4688 → 5156) в единый инцидент по совпадению IP и временного окна,
построил таймлайн и классифицировал как **Persistence (Backdoor)** с последующим C2-соединением.

**Сценарий 4 — Insider threat / anomaly detection.** На логах легитимного пользователя `john`
выявил аномалию по трём независимым признакам одновременно: нетипичное время логона, гео-аномалия
IP (Россия вместо привычного офисного адреса), нехарактерная для пользователя команда с флагом
`-enc`. Ни один признак сам по себе не был бы достаточным — вывод строился на их совпадении.

**Сценарий 5 — Capstone: Data Exfiltration incident.** Полное расследование от алёрта до отчёта:

```
02:00–03:00 → 50x Event 4625 (Brute-Force подбор пароля админа)
03:15       → Event 4720 (создан аккаунт service_account)
03:16       → Event 4728 (добавлен в Administrators — Privilege Escalation)
03:17       → Event 4624 (успешный вход новым аккаунтом)
03:18       → Event 4688 (net localgroup administrators service_account /add)
03:20       → Event 5156 (исходящее соединение, 500 MB отправлено на 8.8.8.8:443)
```

## Вывод (Incident Report — Capstone)

**Title:** Brute-Force + Privilege Escalation + Data Exfiltration

**Severity:** Critical

**Attack Flow:** Атакующий подобрал пароль администратора методом brute-force (50 попыток за
час), создал новый аккаунт `service_account`, немедленно повысил его до Administrators, вошёл
под ним и через PowerShell выгрузил порядка 500 MB данных на внешний IP по 443 порту.

**Evidence (Event IDs):** 4625 (Brute-Force) → 4720 (создание backdoor-аккаунта) → 4728
(Privilege Escalation) → 4688 (закрепление через net.exe) → 5156 (exfiltration).

**Impact:** Скомпрометирован административный аккаунт, произошла утечка ~500 MB данных.

**Recommended Actions:** немедленная сетевая изоляция и блокировка C2-адреса, экстренный сброс
паролей администраторов, полное расследование вектора первичного brute-force (почему 50 неудачных
попыток не были заблокированы политикой lockout), усиление мониторинга privilege escalation
событий (4728) с автоматическим алертингом.

## Инструменты

Windows Event Viewer · Event ID корреляция · Incident timeline reconstruction
