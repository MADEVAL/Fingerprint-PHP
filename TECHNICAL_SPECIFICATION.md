# Техническое задание: PHP-библиотека `globus-studio/fingerprint`

## 1. Общая информация

**Название пакета:** `globus-studio/fingerprint`

**Назначение:** серверная PHP-библиотека для построения вероятностного отпечатка пользователя, устройства или клиента по данным HTTP-запроса, окружения сервера и сетевого контекста.

**Разработчик:** Yevhen Leonidov

**Организация:** GLOBUS.studio

**Целевая публикация:** Packagist, установка через Composer.

**Основная идея:** библиотека не должна обещать абсолютную идентификацию. Она должна вычислять стабильный, объяснимый и настраиваемый fingerprint на основе доступных серверу сигналов, присваивать каждому сигналу вес, оценивать уверенность результата и позволять разработчику управлять приватностью, нормализацией, хранением и сравнением отпечатков.

## 2. Цели проекта

1. Создать современную PHP-библиотеку для идентификации клиента по серверным данным без JavaScript-зависимости.
2. Поддержать разные серверные окружения: Nginx, Apache, IIS, Caddy, LiteSpeed, OpenResty, FrankenPHP, RoadRunner, Swoole, PHP-FPM, FastCGI, CGI, Apache module, CLI server для разработки.
3. Обеспечить поддержку PHP 8.5 и актуальных PHP-практик: строгая типизация, readonly-объекты, enum, value objects, PSR-стандарты, статический анализ, тесты.
4. Дать разработчику готовый API для:
   - сбора сигналов из запроса;
   - нормализации и фильтрации данных;
   - вычисления стабильного хеша;
   - сравнения отпечатков;
   - оценки уверенности и риска;
   - безопасного хранения;
   - интеграции с PSR-7, Symfony, Laravel, Laminas, Slim и обычным PHP.
5. Реализовать расширяемую архитектуру, чтобы можно было добавлять новые источники сигналов без изменения ядра.
6. Сразу заложить требования приватности и соответствия GDPR, ePrivacy, CCPA/CPRA и локальным политикам сайта.

## 3. Не цели проекта

1. Библиотека не должна использовать скрытый клиентский трекинг или обходить настройки приватности пользователя.
2. Библиотека не должна позиционироваться как замена аутентификации, 2FA, сессиям или антифрод-системам.
3. Библиотека не должна хранить персональные данные без явного решения приложения-потребителя.
4. Библиотека не должна выполнять сетевые запросы к внешним GeoIP, threat-intelligence или proxy-detection API по умолчанию.
5. Библиотека не должна зависеть от конкретного фреймворка.
6. Библиотека не должна считать один IP-адрес надежным уникальным идентификатором пользователя.

## 4. Основные сценарии использования

1. **Защита аккаунта:** обнаружение подозрительной смены устройства, сети, прокси или окружения.
2. **Антифрод:** дополнительный сигнал для скоринга заказов, регистраций, платежей, форм обратной связи.
3. **Защита от злоупотреблений:** ограничение массовых регистраций, спама, brute force, password spraying.
4. **Стабильные пользовательские сессии:** мягкая проверка, что текущая сессия похожа на ранее подтвержденную.
5. **Аналитика безопасности:** агрегированные отчеты по типам клиентов, прокси, CDN, аномальным заголовкам.
6. **Rate limiting:** вспомогательный ключ рядом с IP, user id, session id и device id.
7. **Forensic logging:** сохранение объяснимого снимка сигналов для расследования инцидентов.

## 5. Юридические и этические требования

1. В README и документации явно указать, что fingerprint является персональными или псевдонимизированными данными в ряде юрисдикций.
2. Предусмотреть режимы приватности:
   - `strict`: минимум сигналов, только низкорисковые данные, агрессивное усечение IP;
   - `balanced`: рекомендованный режим, достаточный для безопасности без чрезмерного сбора;
   - `maximum`: максимальное количество серверных сигналов, только при наличии правового основания;
   - `custom`: явная настройка источников и весов.
3. По умолчанию не сохранять сырые значения чувствительных заголовков.
4. По умолчанию хешировать итоговый fingerprint с секретной солью приложения.
5. Поддержать ротацию соли через версионирование hash context.
6. Предусмотреть TTL для сохраненных отпечатков.
7. Предусмотреть удаление, экспорт и объяснение сохраненных данных на стороне приложения.
8. Документировать необходимость consent banner или legitimate interest assessment там, где это требуется.
9. Добавить предупреждение: fingerprint нельзя использовать для дискриминации, скрытого слежения или обхода пользовательских настроек приватности.

## 6. Требования к платформе

### 6.1 PHP

1. Минимальная версия: `php >= 8.3`.
2. Обязательная поддержка и тестовая матрица: PHP 8.3, 8.4, 8.5.
3. Подготовленность к PHP 9: отсутствие deprecated API, явные типы, строгие сигнатуры.
4. Файл `composer.json` должен содержать:
   - `"name": "globus-studio/fingerprint"`;
   - `"type": "library"`;
   - `"license": "MIT"` или другая выбранная лицензия;
   - `"minimum-stability": "stable"`;
   - `"prefer-stable": true`;
   - PSR-4 autoload namespace `GlobusStudio\\Fingerprint\\`.

### 6.2 Расширения PHP

Обязательные:

1. `json`.
2. `hash`.
3. `filter`.
4. `mbstring`, если используется нормализация Unicode.

Опциональные:

1. `intl` для расширенной нормализации локалей и Unicode.
2. `sodium` для keyed hashing, если выбран `sodium_crypto_generichash`.
3. `gmp` или `bcmath` не требуются.
4. `geoip` не требуется, интеграции должны быть отдельными адаптерами.

### 6.3 Серверы и SAPI

Библиотека должна корректно работать в окружениях:

1. Nginx + PHP-FPM.
2. Apache + mod_php.
3. Apache + PHP-FPM/FastCGI.
4. IIS + FastCGI.
5. Caddy + PHP-FPM.
6. LiteSpeed/OpenLiteSpeed.
7. OpenResty.
8. FrankenPHP.
9. RoadRunner.
10. Swoole.
11. ReactPHP/Amp через PSR-7 адаптер.
12. Built-in PHP server для локальной разработки.
13. CLI в режиме тестов через synthetic request objects.

## 7. Архитектурные принципы

1. **Framework-agnostic core:** ядро не зависит от Symfony, Laravel, Laminas или PSR-7 реализаций.
2. **PSR-first integration:** отдельные адаптеры для PSR-7 `ServerRequestInterface` и PSR-15 middleware.
3. **Immutable DTO:** собранные данные представлены неизменяемыми value objects.
4. **Deterministic normalization:** одинаковые входные данные дают одинаковый canonical representation.
5. **Configurable entropy:** каждый сигнал имеет вес, стабильность и чувствительность.
6. **Explainability:** результат содержит список использованных сигналов, их normalized value hash, вес и вклад.
7. **Privacy by default:** безопасные настройки по умолчанию.
8. **No hidden globals:** работа с `$_SERVER`, `$_COOKIE`, `$_GET`, `$_POST` только через отдельный request adapter.
9. **Testability:** любой источник данных можно заменить synthetic fixture.
10. **Extensibility:** новые collectors и normalizers подключаются через интерфейсы.

## 8. Предлагаемая структура пакета

```text
src/
  Fingerprint.php
  FingerprintBuilder.php
  FingerprintResult.php
  Configuration/
    FingerprintConfig.php
    PrivacyMode.php
    HashingConfig.php
    SignalConfig.php
  Request/
    RequestContext.php
    RequestContextFactory.php
    NativeServerRequestFactory.php
    HeaderBag.php
    ServerBag.php
    CookieBag.php
  Collector/
    SignalCollectorInterface.php
    HeaderSignalCollector.php
    NetworkSignalCollector.php
    TlsSignalCollector.php
    CookieSignalCollector.php
    ServerSignalCollector.php
    ProxySignalCollector.php
    FrameworkSignalCollector.php
  Signal/
    Signal.php
    SignalName.php
    SignalType.php
    SignalSensitivity.php
    SignalStability.php
    SignalSet.php
  Normalizer/
    NormalizerInterface.php
    HeaderNormalizer.php
    IpNormalizer.php
    UserAgentNormalizer.php
    AcceptLanguageNormalizer.php
    EncodingNormalizer.php
    TimezoneNormalizer.php
  Hasher/
    FingerprintHasherInterface.php
    HmacSha256Hasher.php
    SodiumHasher.php
    CanonicalJsonEncoder.php
  Matcher/
    FingerprintMatcher.php
    MatchResult.php
    MatchLevel.php
  Storage/
    FingerprintStorageInterface.php
    InMemoryFingerprintStorage.php
  Integration/
    Psr7/
    Psr15/
    Symfony/
    Laravel/
  Exception/
    FingerprintException.php
    ConfigurationException.php
    UnsupportedEnvironmentException.php
```

## 9. Публичный API

### 9.1 Базовое использование без фреймворка

```php
use GlobusStudio\Fingerprint\FingerprintBuilder;
use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;

$config = FingerprintConfig::balanced(
    secret: $_ENV['APP_FINGERPRINT_SECRET']
);

$result = FingerprintBuilder::fromGlobals($config)->build();

$fingerprintId = $result->id();
$confidence = $result->confidence();
$signals = $result->signals();
```

### 9.2 PSR-7

```php
$result = $fingerprinter->fromPsr7Request($request)->build();
```

### 9.3 Symfony

```php
$result = $fingerprinter->fromSymfonyRequest($request)->build();
```

### 9.4 Laravel

```php
$result = app(Fingerprinter::class)->fromIlluminateRequest($request)->build();
```

### 9.5 Сравнение отпечатков

```php
$match = $matcher->compare($current, $known);

if ($match->level()->isSuspicious()) {
    // trigger step-up authentication
}
```

## 10. Модель результата

`FingerprintResult` должен содержать:

1. `id`: итоговый стабильный fingerprint hash.
2. `version`: версия алгоритма.
3. `profile`: имя профиля конфигурации.
4. `createdAt`: время создания.
5. `confidence`: число от 0 до 100.
6. `entropyScore`: оценка уникальности сигналов.
7. `stabilityScore`: оценка ожидаемой стабильности во времени.
8. `riskScore`: дополнительный риск, если включены risk collectors.
9. `signals`: список нормализованных сигналов.
10. `usedSignalNames`: имена сигналов, которые вошли в итоговый hash.
11. `ignoredSignalNames`: имена сигналов, отброшенные конфигурацией или пустыми значениями.
12. `environment`: краткие сведения о SAPI и сервере.
13. `debug`: опциональная диагностическая информация, выключена по умолчанию.

## 11. Signal model

Каждый `Signal` должен иметь:

1. `name`: стабильное машинное имя, например `header.user_agent`.
2. `type`: `header`, `network`, `tls`, `cookie`, `server`, `proxy`, `framework`, `derived`.
3. `rawValue`: исходное значение, доступно только в debug-режиме и может быть скрыто.
4. `normalizedValue`: нормализованное значение или canonical representation.
5. `hashedValue`: hash normalized value для безопасного объяснения.
6. `weight`: вес в итоговом fingerprint.
7. `stability`: `volatile`, `medium`, `stable`.
8. `sensitivity`: `low`, `medium`, `high`, `special`.
9. `source`: откуда получен сигнал, например `$_SERVER.HTTP_USER_AGENT`.
10. `included`: попал ли сигнал в итоговый fingerprint.
11. `reason`: почему сигнал включен или исключен.

## 12. Источники данных

### 12.1 HTTP headers

Библиотека должна собирать и нормализовать следующие заголовки, если они доступны:

1. `User-Agent`.
2. `Accept`.
3. `Accept-Language`.
4. `Accept-Encoding`.
5. `Accept-Charset`, устаревший, но иногда полезный.
6. `DNT`.
7. `Sec-GPC`.
8. `Upgrade-Insecure-Requests`.
9. `Sec-CH-UA`.
10. `Sec-CH-UA-Mobile`.
11. `Sec-CH-UA-Platform`.
12. `Sec-CH-UA-Platform-Version`.
13. `Sec-CH-UA-Arch`.
14. `Sec-CH-UA-Bitness`.
15. `Sec-CH-UA-Full-Version`.
16. `Sec-CH-UA-Full-Version-List`.
17. `Sec-CH-UA-Model`.
18. `Sec-CH-UA-WoW64`.
19. `Sec-Fetch-Site`.
20. `Sec-Fetch-Mode`.
21. `Sec-Fetch-Dest`.
22. `Sec-Fetch-User`.
23. `Cache-Control`.
24. `Pragma`.
25. `Connection`, если сервер не удалил hop-by-hop headers.
26. `TE`, если доступен.
27. `Via`.
28. `Forwarded`.
29. `X-Forwarded-For`.
30. `X-Forwarded-Host`.
31. `X-Forwarded-Proto`.
32. `X-Forwarded-Port`.
33. `X-Real-IP`.
34. `True-Client-IP`.
35. `CF-Connecting-IP`.
36. `CF-IPCountry`.
37. `CF-Ray`.
38. `CF-Visitor`.
39. `CDN-Loop`.
40. `Fastly-Client-IP`.
41. `X-Akamai-Edgescape`.
42. `X-Client-IP`.
43. `Client-IP`.
44. `X-Cluster-Client-IP`.
45. `X-Original-Forwarded-For`.
46. `X-Request-ID` и аналоги не должны входить в fingerprint по умолчанию, так как они request-scoped.
47. `Authorization` никогда не должен входить в fingerprint.
48. `Cookie` не должен входить целиком, только явно разрешенные cookie names.
49. `Referer` не должен входить по умолчанию, так как он нестабилен и чувствителен.
50. `Origin` может использоваться только как request-context/risk signal, не как стабильный identity signal.

### 12.2 Порядок заголовков

Порядок заголовков может быть полезным сигналом, но в PHP он часто недоступен или искажен сервером.

Требования:

1. Реализовать `HeaderOrderSignalCollector`, но сделать его опциональным.
2. Для PHP-FPM через Nginx и IIS считать порядок заголовков ненадежным, потому что сервер передает PHP нормализованные переменные окружения.
3. Для Apache `apache_request_headers()` может сохранить порядок в некоторых окружениях, но это не гарантируется стандартом.
4. Для PSR-7 порядок заголовков обычно зависит от реализации и может не соответствовать wire order.
5. Для RoadRunner, Swoole, ReactPHP и Amp возможно получить порядок ближе к исходному, если runtime предоставляет raw request.
6. В итоговом результате сигнал должен содержать `reliability: low|medium|high`.
7. По умолчанию использовать не сырой порядок всех заголовков, а canonical sequence только безопасных header names.
8. Исключить из sequence request-specific headers: `Host`, `Content-Length`, `Content-Type` для multipart, `Cookie`, `Authorization`, `X-Request-ID`, `Traceparent`, `Tracestate`.
9. Поддержать отдельный hash `header_order_hash`, если порядок действительно доступен.
10. В документации честно указать, что для большинства классических PHP-развертываний порядок заголовков не является надежным fingerprint-сигналом.

### 12.3 Наполнение заголовков

Для каждого заголовка нужно задать правила нормализации:

1. Trim пробелов по краям.
2. Collapse последовательностей whitespace там, где это безопасно.
3. Header names приводить к lowercase canonical form.
4. Multi-value headers сортировать только там, где порядок значения не имеет смысла.
5. Для `Accept`, `Accept-Language`, `Accept-Encoding` сохранять q-values, но нормализовать формат чисел.
6. Для `User-Agent` сохранять значимые токены, но уметь строить derived profile: browser family, major version, engine, OS family, device class.
7. Для Client Hints парсить structured headers согласно RFC 8941 там, где применимо.
8. Для `Forwarded` парсить RFC 7239.
9. Для `X-Forwarded-For` хранить цепочку IP только после trust proxy validation.
10. Для `Cookie` использовать allowlist имен, а не все cookies.
11. Для заголовков с потенциальными секретами использовать denylist.

### 12.4 Network/IP signals

Сигналы:

1. `remote_addr`: `$_SERVER['REMOTE_ADDR']`.
2. `client_ip`: вычисленный IP с учетом доверенных прокси.
3. `ip_version`: IPv4 или IPv6.
4. `ip_prefix`: усеченная сеть, например IPv4 `/24`, IPv6 `/48` или `/56`.
5. `ip_is_private`.
6. `ip_is_reserved`.
7. `ip_is_loopback`.
8. `ip_is_link_local`.
9. `ip_is_proxy_header_present`.
10. `proxy_chain_length`.
11. `trusted_proxy_match`.
12. `asn`, `organization`, `country`, `region`, `city` только через опциональные провайдеры и не по умолчанию.
13. `connection_port`: `REMOTE_PORT`, низкая стабильность, по умолчанию не включать.

Правила:

1. Не использовать полный IP в режиме `strict`.
2. В режиме `balanced` использовать IP prefix, а не полный IP.
3. В режиме `maximum` разрешить полный IP только если `allowFullIpAddress(true)`.
4. Для IPv6 не использовать весь адрес как стабильный идентификатор, так как privacy extensions часто меняют interface identifier.
5. Trust proxy должен быть явно настроен. Нельзя доверять `X-Forwarded-For` от любого клиента.

### 12.5 TLS/HTTPS signals

В PHP доступны не всегда. Поддержать как best-effort:

1. `HTTPS` flag.
2. `REQUEST_SCHEME`.
3. `SERVER_PORT`.
4. `SSL_PROTOCOL`, если сервер передал.
5. `SSL_CIPHER`, если сервер передал.
6. `SSL_CLIENT_VERIFY`, если используется client certificate.
7. `SSL_CLIENT_S_DN`, `SSL_CLIENT_I_DN`, `SSL_CLIENT_M_SERIAL`, только если явно разрешено и с высокой чувствительностью.
8. `HTTP2`/`HTTP3` признаки, если сервер передает `SERVER_PROTOCOL` или runtime API.

Ограничения:

1. JA3/JA4 fingerprint обычно недоступен в обычном PHP за Nginx/Apache/IIS.
2. Если нужен JA3/JA4, библиотека должна поддерживать внешний collector через reverse proxy, WAF, Envoy, Nginx module, OpenResty, CDN или отдельный header от доверенного инфраструктурного слоя.
3. Любые TLS client certificate данные считаются sensitive/high и выключены по умолчанию.

### 12.6 Server/environment signals

Сигналы окружения не идентифицируют пользователя напрямую, но помогают диагностике:

1. `server_software`.
2. `server_protocol`.
3. `gateway_interface`.
4. `request_method`.
5. `request_uri_shape`, без query string по умолчанию.
6. `sapi_name`.
7. `host`, если разрешено.
8. `is_https`.
9. `http_version`.

Не включать по умолчанию в стабильный fingerprint:

1. `REQUEST_TIME`.
2. `REQUEST_TIME_FLOAT`.
3. `UNIQUE_ID`.
4. `REQUEST_ID`.
5. `SCRIPT_FILENAME`.
6. `DOCUMENT_ROOT`.
7. Любые filesystem paths.

### 12.7 Cookie signals

Подход:

1. Не fingerprint-ить весь заголовок `Cookie`.
2. Поддержать allowlist cookie names.
3. Для каждой cookie можно выбрать режим:
   - presence only;
   - hash value;
   - normalized value;
   - ignored.
4. Сессионные cookie вроде `PHPSESSID`, `laravel_session`, `symfony_session` по умолчанию использовать только как auxiliary/session signal, не как device fingerprint.
5. Cookie consent state можно включать как risk/context signal.
6. Значения cookies считать high sensitivity.

### 12.8 Derived browser signals

Из `User-Agent` и Client Hints вычислять:

1. Browser family.
2. Browser major version.
3. Browser full version, если доступно и разрешено.
4. Rendering engine.
5. OS family.
6. OS major version.
7. Device class: desktop, mobile, tablet, bot, tv, console, unknown.
8. Bot likelihood.
9. Client hints consistency: совпадают ли UA и CH.
10. Frozen UA detection.

Рекомендация: использовать `ua-parser/uap-php` или отдельный lightweight parser как optional dependency. Ядро не должно жестко зависеть от тяжелого парсера.

### 12.9 Bot/proxy/anomaly signals

Опциональные риск-сигналы:

1. Несогласованность `User-Agent` и `Sec-CH-UA`.
2. Отсутствие типичных browser headers.
3. Подозрительный порядок или набор заголовков.
4. Наличие `Via`, `Forwarded`, CDN headers.
5. Много IP в `X-Forwarded-For`.
6. Private IP в forwarded chain.
7. Несоответствие `Host` и `X-Forwarded-Host`.
8. Несоответствие `X-Forwarded-Proto` и HTTPS.
9. Headless/browser automation признаки только по server-side headers, без JS.
10. CLI/library user agents: curl, wget, python-requests, Guzzle, Go-http-client, Java, okhttp, httpx.
11. Empty или слишком короткий `Accept-Language`.
12. Нестандартный `Accept-Encoding`.
13. Нестандартные `Sec-Fetch-*`.

Эти сигналы должны влиять на `riskScore`, но не обязательно на стабильный `fingerprintId`.

## 13. Trust proxy model

Критически важное требование: корректная работа за reverse proxy, CDN и load balancer.

### 13.1 Настройки

1. `trustedProxies`: CIDR list, IP list или preset.
2. `trustedHeaders`: список разрешенных proxy headers.
3. `cloudflare`: preset для Cloudflare.
4. `fastly`: preset для Fastly.
5. `akamai`: preset для Akamai.
6. `awsAlb`: preset для AWS ALB/ELB.
7. `nginxProxy`: generic preset.
8. `symfonyTrustedProxiesBridge`: интеграция с настройками Symfony.
9. `laravelTrustedProxyBridge`: интеграция с trustedproxy Laravel.

### 13.2 Алгоритм client IP

1. Начать с `REMOTE_ADDR`.
2. Проверить, является ли `REMOTE_ADDR` доверенным прокси.
3. Если нет, игнорировать все forwarded headers.
4. Если да, разобрать разрешенные headers в порядке приоритета.
5. Валидировать каждый IP через `filter_var(..., FILTER_VALIDATE_IP)`.
6. Удалить private/reserved IP из публичной цепочки, если это настроено.
7. Определить первый недоверенный upstream client IP.
8. Сохранить объяснение выбора.

## 14. Fingerprint algorithm

### 14.1 Canonical representation

Итоговый hash должен строиться не из произвольного массива, а из стабильного canonical JSON:

1. Сортировка signal names по алфавиту.
2. Стабильное кодирование JSON без неявного изменения типов.
3. Явная версия схемы.
4. Явная версия алгоритма.
5. Явная версия профиля нормализации.
6. Исключение `null`, пустых и недоступных сигналов по заданному правилу.
7. Отдельное поле `saltVersion` или `keyVersion`, но не сама соль.

Пример canonical payload:

```json
{
  "algorithm": "gsfp-v1",
  "profile": "balanced",
  "signals": {
    "browser.family": "Chrome",
    "browser.major": "124",
    "header.accept_language": "en-US,en;q=0.9",
    "ip.prefix": "203.0.113.0/24"
  }
}
```

### 14.2 Hashing

1. Основной алгоритм: HMAC-SHA-256.
2. Секрет обязателен для production.
3. Без секрета разрешить только dev mode с явным предупреждением.
4. Опционально поддержать BLAKE2b через Sodium.
5. Итоговый ID кодировать как lowercase hex или base64url.
6. Добавить prefix версии: `gsfp_v1_...`.
7. Не использовать MD5, SHA-1 и несоленые хеши.

### 14.3 Confidence score

`confidence` должен учитывать:

1. Количество доступных сигналов.
2. Их веса.
3. Стабильность сигналов.
4. Чувствительность сигналов.
5. Противоречия между сигналами.
6. Наличие доверенного proxy context.
7. Долю сигналов, которые были недоступны.

Пример уровней:

1. `0-30`: low confidence.
2. `31-60`: medium confidence.
3. `61-80`: high confidence.
4. `81-100`: very high confidence.

### 14.4 Entropy score

Оценивать не как криптографическую энтропию, а как практическую редкость набора сигналов:

1. Generic browser UA имеет низкую энтропию.
2. Полный набор UA + Accept-Language + Client Hints + IP prefix имеет среднюю энтропию.
3. Дополнительные trusted TLS/proxy/ASN сигналы повышают энтропию.
4. Request-scoped значения не должны повышать стабильный entropy score.

### 14.5 Stability score

1. `User-Agent` major version: medium.
2. Full browser version: volatile.
3. Accept-Language: stable/medium.
4. Accept-Encoding: medium.
5. IP full: volatile/medium.
6. IP prefix: medium.
7. Client Hints platform: medium/stable.
8. Header order: low/medium, зависит от SAPI.
9. Cookies: зависит от cookie type.

## 15. Matching algorithm

Помимо точного совпадения hash, библиотека должна уметь сравнивать два `FingerprintResult`.

### 15.1 Требования

1. `exactMatch`: совпал итоговый hash.
2. `partialMatch`: совпала часть сигналов.
3. `distance`: числовое расстояние 0-100.
4. `changedSignals`: список изменившихся сигналов.
5. `stableSignalsMatched`: количество совпавших стабильных сигналов.
6. `volatileSignalsChanged`: количество изменившихся нестабильных сигналов.
7. `riskReasons`: объяснение подозрительных отличий.

### 15.2 Уровни результата

1. `same`: высокая вероятность того же клиента.
2. `similar`: вероятно тот же клиент, но часть сигналов изменилась.
3. `changed`: существенное изменение окружения.
4. `suspicious`: изменение затрагивает стабильные или риск-сигналы.
5. `unknown`: недостаточно данных.

### 15.3 Примеры правил

1. Изменился IP внутри того же `/24`, UA и language совпали: `similar`.
2. Изменился UA major, IP prefix совпал, language совпал: `similar` или `changed`.
3. Изменились UA family, OS, Accept-Language и IP ASN: `suspicious`.
4. Появился proxy chain при прежнем аккаунте: повысить `riskScore`.
5. Пропали Client Hints, но UA похож: не считать автоматическим fraud.

## 16. Конфигурация

### 16.1 Пример конфигурации

```php
$config = FingerprintConfig::create()
    ->withPrivacyMode(PrivacyMode::Balanced)
    ->withSecret($_ENV['APP_FINGERPRINT_SECRET'])
    ->withTrustedProxies(['10.0.0.0/8', '172.16.0.0/12'])
    ->withTrustedHeaders(['x-forwarded-for', 'x-forwarded-proto'])
    ->withIpPrefixing(ipv4: 24, ipv6: 56)
    ->includeClientHints(true)
    ->includeHeaderOrder(false)
    ->includeCookies(['device_consent' => 'presence'])
    ->excludeHeaders(['authorization', 'cookie'])
    ->build();
```

### 16.2 Обязательные настройки

1. `secret`.
2. `privacyMode`.
3. `algorithmVersion`.
4. `trustedProxies`.
5. `ipStrategy`.
6. `enabledCollectors`.
7. `disabledSignals`.
8. `cookieAllowlist`.
9. `debug`.
10. `rawValuePolicy`.

### 16.3 Профили

`strict`:

1. No full IP.
2. IP prefix only.
3. No cookie values.
4. No TLS certificate data.
5. No full UA version.
6. No header order by default.
7. No raw values in result.

`balanced`:

1. IP prefix.
2. UA derived values.
3. Accept-Language normalized.
4. Accept-Encoding normalized.
5. Client Hints if present.
6. Cookie presence only for allowlist.
7. Header order off by default.

`maximum`:

1. Full IP allowed only by explicit flag.
2. Header order allowed if reliable.
3. Selected cookie value hashes allowed.
4. TLS signals allowed if exposed by server.
5. External enrichment adapters allowed.

## 17. Header normalization details

### 17.1 `User-Agent`

1. Keep raw hash, not raw value, unless debug explicitly enabled.
2. Normalize whitespace.
3. Parse family, major, minor, patch where possible.
4. Extract OS family and version.
5. Detect bots and libraries.
6. Avoid relying on full UA as stable identity because modern browsers freeze or reduce UA.

### 17.2 `Accept-Language`

1. Lowercase language tags except region if canonicalizer supports it.
2. Normalize separators.
3. Normalize q-values: `q=1.0` to `q=1`, `q=.9` to `q=0.9`.
4. Preserve order because preference order matters.
5. Optionally produce reduced version: top language only.

### 17.3 `Accept-Encoding`

1. Lowercase tokens.
2. Normalize q-values.
3. Preserve order by default.
4. Recognize common tokens: gzip, br, deflate, zstd.
5. Unknown encodings keep as token hash if configured.

### 17.4 `Accept`

1. Parse media ranges.
2. Normalize whitespace.
3. Preserve order and q-values.
4. Optionally collapse to coarse profile: html/json/image/api/unknown.

### 17.5 Client Hints

1. Parse structured values safely.
2. Treat missing hints as normal behavior.
3. Support reduced UA world.
4. Do not send `Accept-CH` headers from core library automatically; this is responsibility приложения.
5. Provide helper documentation for enabling Client Hints via server/framework.

## 18. Server-specific notes

### 18.1 Nginx + PHP-FPM

1. Headers are exposed as `$_SERVER['HTTP_*']`.
2. Header names are uppercased and hyphens become underscores.
3. Header order is generally lost.
4. `REMOTE_ADDR` is address of direct peer, often load balancer/proxy.
5. Need explicit `fastcgi_param` для нестандартных headers, если они не передаются.
6. For TLS info, Nginx must pass variables through `fastcgi_param SSL_PROTOCOL $ssl_protocol;` etc.

### 18.2 Apache

1. `apache_request_headers()` may be available.
2. `getallheaders()` may be available outside Apache in newer PHP, but behavior depends on SAPI.
3. `REMOTE_ADDR` may be client or proxy depending on deployment.
4. `mod_remoteip` can rewrite client IP. Library must record whether rewritten headers exist if possible.
5. TLS vars require Apache SSL environment export.

### 18.3 IIS + FastCGI

1. Headers are exposed through server variables.
2. Header order is not reliable.
3. Some names may differ or be absent depending on FastCGI settings.
4. Client IP can be affected by ARR and proxy settings.
5. Need support for `X-Original-For`, `X-Forwarded-For`, `X-ARR-LOG-ID` as context only.

### 18.4 Caddy, LiteSpeed, OpenResty

1. Treat as generic reverse proxy/FastCGI unless runtime provides richer data.
2. Document known header behavior.
3. Encourage explicit trusted proxy configuration.

### 18.5 RoadRunner/Swoole

1. Prefer PSR-7/request object integration.
2. Do not read global state in long-running workers.
3. Avoid static mutable cache tied to one request.
4. Ensure collectors are stateless or reset per request.

## 19. Security requirements

1. All secrets must be injected through config, not hardcoded.
2. Use constant-time comparison for fingerprint IDs where security-relevant.
3. Never include `Authorization`, bearer tokens, API keys, CSRF tokens, passwords, request bodies or full query strings in fingerprint.
4. Provide header denylist by default:
   - `authorization`;
   - `proxy-authorization`;
   - `cookie`, unless explicitly parsed by allowlist;
   - `set-cookie`;
   - `x-api-key`;
   - `x-auth-token`;
   - `x-csrf-token`;
   - `csrf-token`;
   - `x-xsrf-token`.
5. Validate all IPs strictly.
6. Protect against header spoofing by trust proxy model.
7. Handle malformed headers without exceptions in normal mode.
8. Add max header length limits to avoid memory abuse.
9. Add max header count limits.
10. Avoid logging raw sensitive values.
11. Provide `RedactorInterface` for safe debug logs.
12. Support algorithm/key versioning for rotation.

## 20. Privacy requirements

1. Raw values disabled by default.
2. Debug mode must be explicit and documented as unsafe for production logs.
3. Allow per-signal sensitivity policy.
4. Allow disabling high-sensitivity collectors globally.
5. Provide data minimization profile.
6. Provide `FingerprintResult::toSafeArray()`.
7. Provide `FingerprintResult::toDebugArray()` only when allowed.
8. Support retention metadata: `ttl`, `createdAt`, `expiresAt`.
9. Document lawful basis and consent requirements.
10. Provide examples of privacy-friendly deployment.

## 21. Exceptions and error handling

1. Invalid configuration throws `ConfigurationException`.
2. Unsupported runtime feature throws only when feature is required; otherwise collector returns unavailable signal.
3. Malformed input should produce ignored signal with reason, not fatal error.
4. Missing secret in production throws exception.
5. Missing optional extension should disable related feature with warning object.
6. Public API should not emit PHP notices/warnings on malformed server arrays.

## 22. Logging and observability

1. PSR-3 logger optional.
2. Log levels:
   - `debug`: collector details, without raw sensitive values;
   - `info`: algorithm version/profile;
   - `warning`: misconfigured trusted proxy, missing secret in dev;
   - `error`: unexpected collector failure.
3. Provide diagnostics object:
   - unavailable collectors;
   - ignored signals;
   - suspicious proxy configuration;
   - SAPI limitations;
   - privacy mode warnings.
4. No logging by default unless logger injected.

## 23. Framework integrations

### 23.1 PSR-7/PSR-15

1. Middleware computes fingerprint and attaches result as request attribute.
2. Attribute name configurable, default `globus_fingerprint`.
3. No response mutation by default.
4. Optional response header disabled by default.

### 23.2 Symfony

1. Service definition.
2. Request listener или argument resolver.
3. Config package recipe optional.
4. Bridge to trusted proxies.

### 23.3 Laravel

1. ServiceProvider.
2. Facade optional.
3. Middleware.
4. Config publish command.
5. Bridge to trusted proxies and request object.

### 23.4 Plain PHP

1. `FingerprintBuilder::fromGlobals()`.
2. Minimal bootstrap example.
3. No framework dependency.

## 24. Storage

Ядро не должно требовать базу данных. Предусмотреть интерфейс:

```php
interface FingerprintStorageInterface
{
    public function save(string $subjectId, FingerprintResult $result): void;

    public function findLatestBySubject(string $subjectId): ?FingerprintResult;

    /** @return list<FingerprintResult> */
    public function findBySubject(string $subjectId, int $limit = 10): array;

    public function deleteBySubject(string $subjectId): void;
}
```

Реализации:

1. `InMemoryFingerprintStorage` для тестов.
2. Документированные примеры для PDO.
3. Optional packages в будущем:
   - `globus-studio/fingerprint-laravel`;
   - `globus-studio/fingerprint-symfony`;
   - `globus-studio/fingerprint-doctrine`.

## 25. Composer dependencies

### 25.1 Production dependencies

Ядро должно иметь минимум зависимостей:

1. `psr/http-message` optional или в `suggest`, если PSR-7 адаптер вынесен.
2. `psr/log` optional.
3. `psr/clock` optional или собственный clock interface.
4. `symfony/polyfill-*` только если реально нужно.

### 25.2 Dev dependencies

1. `phpunit/phpunit` или `pestphp/pest`.
2. `phpstan/phpstan`.
3. `vimeo/psalm` опционально.
4. `friendsofphp/php-cs-fixer` или `squizlabs/php_codesniffer`.
5. `infection/infection` для mutation testing.
6. `rector/rector` для upgrade safety.
7. `composer-normalize`.
8. `phpbench/phpbench` для benchmark.

## 26. Кодстайл и качество

1. `declare(strict_types=1);` во всех PHP-файлах.
2. PSR-12 или PER-CS.
3. Typed properties, return types, parameter types.
4. Readonly classes/value objects где применимо.
5. Enum для режимов, уровней и типов сигналов.
6. Запрет one-letter variable names.
7. Маленькие классы с одной ответственностью.
8. Composer scripts:
   - `test`;
   - `test:coverage`;
   - `analyse`;
   - `cs`;
   - `cs:fix`;
   - `infection`;
   - `bench`.
9. PHPStan level 9 или максимальный доступный.
10. Покрытие тестами не ниже 85% для core.
11. Mutation score целевой: 70%+ для алгоритмов нормализации и matching.

## 27. Тестирование

### 27.1 Unit tests

1. Header normalization.
2. IP parsing.
3. Trusted proxy resolution.
4. Canonical JSON encoding.
5. Hashing.
6. Signal weighting.
7. Confidence scoring.
8. Matching.
9. Privacy profiles.
10. Redaction.

### 27.2 Integration tests

1. Native globals request.
2. PSR-7 request.
3. Symfony request.
4. Laravel request, если интеграция в ядре или отдельном пакете.
5. Nginx-like server variables fixture.
6. Apache-like fixture.
7. IIS-like fixture.
8. Cloudflare fixture.
9. AWS ALB fixture.
10. Malformed headers.

### 27.3 Compatibility tests

1. PHP 8.3.
2. PHP 8.4.
3. PHP 8.5.
4. Lowest dependencies.
5. Highest dependencies.
6. Windows.
7. Linux.
8. macOS optional.

### 27.4 Security tests

1. Authorization header excluded.
2. Cookie not included unless allowlisted.
3. Full IP excluded in strict/balanced profiles.
4. Spoofed `X-Forwarded-For` ignored when proxy untrusted.
5. Header length limits.
6. Malformed Client Hints do not crash.
7. Constant-time comparison used where needed.

### 27.5 Golden tests

Создать fixtures с ожидаемыми fingerprint IDs для стабильности алгоритма:

1. `fixtures/nginx-chrome.json`.
2. `fixtures/apache-firefox.json`.
3. `fixtures/iis-edge.json`.
4. `fixtures/cloudflare-safari.json`.
5. `fixtures/mobile-chrome.json`.
6. `fixtures/curl-client.json`.
7. `fixtures/bot-client.json`.

При изменении алгоритма требуется новая версия `gsfp-v2`, а не тихое изменение `gsfp-v1`.

## 28. CI/CD

GitHub Actions workflows:

1. `ci.yml`:
   - checkout;
   - setup PHP 8.3, 8.4, 8.5;
   - composer validate;
   - composer install;
   - code style check;
   - static analysis;
   - tests.
2. `lowest-deps.yml`:
   - `composer update --prefer-lowest --prefer-stable`;
   - tests.
3. `mutation.yml` optional/manual.
4. `release.yml`:
   - validate tag;
   - generate changelog;
   - create GitHub release.
5. `packagist.yml` optional, if using webhook usually not needed.

## 29. Документация

Обязательные файлы:

1. `README.md`.
2. `CHANGELOG.md`.
3. `LICENSE`.
4. `SECURITY.md`.
5. `CONTRIBUTING.md`.
6. `CODE_OF_CONDUCT.md` optional.
7. `docs/privacy.md`.
8. `docs/configuration.md`.
9. `docs/signals.md`.
10. `docs/trusted-proxies.md`.
11. `docs/frameworks/laravel.md`.
12. `docs/frameworks/symfony.md`.
13. `docs/frameworks/psr-7.md`.
14. `docs/server/nginx.md`.
15. `docs/server/apache.md`.
16. `docs/server/iis.md`.
17. `docs/algorithm-versioning.md`.
18. `docs/testing.md`.

README должен содержать:

1. Короткое описание.
2. Установку.
3. Быстрый старт.
4. Важное предупреждение о приватности.
5. Пример balanced config.
6. Пример trusted proxies.
7. Пример matching.
8. Поддерживаемые версии PHP.
9. Ссылки на подробные docs.

## 30. Packagist requirements

1. Валидный `composer.json`.
2. Семантическое версионирование.
3. Git tags: `v0.1.0`, `v1.0.0`.
4. README на английском желательно, можно дополнительно русский вариант.
5. Keywords:
   - `fingerprint`;
   - `device-fingerprint`;
   - `browser-fingerprint`;
   - `php`;
   - `security`;
   - `fraud-detection`;
   - `risk-scoring`;
   - `psr-7`;
   - `laravel`;
   - `symfony`.
6. Composer extra для branch alias optional.
7. GitHub repository linked to Packagist.
8. Auto-update через Packagist GitHub hook.

## 31. Версионирование алгоритма

1. Любое изменение canonical payload, набора default signals или hashing меняет `algorithmVersion`.
2. Патч-релизы не должны менять fingerprint output для той же версии алгоритма.
3. Minor-релиз может добавить новый алгоритм, но старый остается доступным.
4. Major-релиз может менять default algorithm.
5. Результат должен явно хранить `algorithmVersion`.
6. Provide migration guide for `gsfp-v1` to `gsfp-v2`.

## 32. Производительность

Требования:

1. Core fingerprint build target: менее 1 мс на обычном запросе без внешних enrichers.
2. Memory overhead target: менее 1 MB на request для balanced profile.
3. No network IO in core.
4. Lazy optional parsers.
5. Cache compiled config.
6. Avoid regex backtracking risks.
7. Benchmarks for:
   - simple request;
   - request with many headers;
   - proxy chain;
   - Client Hints parsing;
   - matching 100 known fingerprints.

## 33. Расширяемость

Интерфейсы:

```php
interface SignalCollectorInterface
{
    public function collect(RequestContext $request, FingerprintConfig $config): SignalSet;
}

interface NormalizerInterface
{
    public function normalize(mixed $value, NormalizationContext $context): NormalizedValue;
}

interface FingerprintHasherInterface
{
    public function hash(CanonicalPayload $payload, HashingConfig $config): string;
}
```

Плагины должны иметь возможность:

1. Добавлять collector.
2. Добавлять normalizer.
3. Добавлять signal weight policy.
4. Добавлять risk rule.
5. Добавлять storage adapter.
6. Добавлять framework integration.

## 34. Risk scoring

Отдельно от fingerprint identity реализовать risk scoring.

Примеры причин риска:

1. `untrusted_forwarded_header`.
2. `proxy_chain_changed`.
3. `ua_ch_mismatch`.
4. `missing_browser_headers`.
5. `automation_user_agent`.
6. `impossible_header_combination`.
7. `ip_prefix_changed`.
8. `asn_changed`.
9. `language_changed`.
10. `tls_profile_changed`, если доступно.

`RiskResult` должен содержать:

1. `score`: 0-100.
2. `level`: low, medium, high, critical.
3. `reasons`.
4. `recommendedAction`: allow, monitor, step_up, block, manual_review.

Важно: библиотека не должна самостоятельно блокировать пользователей. Она только возвращает результат.

## 35. Data safety и redaction

1. `rawValue` по умолчанию `null`.
2. `safeValue` может быть:
   - full для low sensitivity;
   - truncated для medium;
   - hashed для high;
   - omitted для special.
3. `toArray()` должен иметь режимы:
   - `safe`;
   - `storage`;
   - `debug`.
4. Debug mode требует `allowRawValues: true`.
5. В логах всегда использовать `safe`.

## 36. Пример default weights

```text
browser.family: 8
browser.major: 6
browser.engine: 4
os.family: 6
os.major: 4
device.class: 4
header.accept_language: 7
header.accept_encoding: 5
header.accept: 4
client_hints.platform: 6
client_hints.mobile: 4
client_hints.brands: 5
ip.prefix: 8
proxy.chain_shape: 3
tls.protocol: 3
header.order_hash: 2
cookie.allowlisted_presence: 3
```

Default weights должны быть конфигурируемыми.

## 37. Ограничения и честные предупреждения

1. Серверный fingerprint слабее гибридного fingerprint с клиентскими сигналами.
2. NAT, VPN, corporate proxy и mobile networks снижают точность.
3. Современные браузеры уменьшают entropy через privacy protections.
4. IP-адрес часто меняется и не должен быть главным идентификатором.
5. Header order в PHP чаще всего недоступен в исходном виде.
6. Client Hints требуют политики браузера и могут отсутствовать.
7. CDN и reverse proxy могут переписывать заголовки.
8. Fingerprint collision возможен.
9. Fingerprint drift неизбежен после обновлений браузера, ОС, смены сети.
10. Любое решение по блокировке должно использовать несколько факторов.

## 38. Roadmap разработки

### Этап 1. MVP core, `v0.1.0`

1. Composer package skeleton.
2. Core config.
3. Native request context.
4. Header collector.
5. Network collector.
6. Basic normalizers.
7. HMAC-SHA-256 hasher.
8. FingerprintResult.
9. Balanced profile.
10. Unit tests.
11. README quick start.

### Этап 2. Proxy and privacy, `v0.2.0`

1. Trust proxy model.
2. IP prefix strategies.
3. Privacy profiles.
4. Redaction.
5. Safe array export.
6. Security tests.
7. Nginx/Apache/IIS docs.

### Этап 3. Matching and risk, `v0.3.0`

1. FingerprintMatcher.
2. MatchResult.
3. Confidence score.
4. Risk score.
5. Bot/proxy anomaly rules.
6. Golden tests.

### Этап 4. Framework adapters, `v0.4.0`

1. PSR-7 adapter.
2. PSR-15 middleware.
3. Symfony bridge.
4. Laravel bridge.
5. Integration docs.

### Этап 5. Stabilization, `v0.9.0`

1. Algorithm freeze for `gsfp-v1`.
2. Full CI matrix.
3. Static analysis level max.
4. Performance benchmarks.
5. Security review.
6. Documentation polish.

### Этап 6. Stable release, `v1.0.0`

1. Public API freeze.
2. SemVer policy.
3. Packagist publication.
4. GitHub release.
5. Upgrade guide.
6. Production readiness checklist.

## 39. Definition of Done для `v1.0.0`

1. Пакет устанавливается через Composer.
2. Все public classes имеют строгие типы.
3. Core не зависит от фреймворков.
4. PHP 8.3, 8.4, 8.5 проходят CI.
5. Windows и Linux проходят CI.
6. PHPStan на максимальном уровне проходит без baseline или с минимальным documented baseline.
7. Unit и integration tests проходят.
8. Core coverage не ниже 85%.
9. Golden tests фиксируют output `gsfp-v1`.
10. README и docs готовы.
11. Privacy warning присутствует.
12. Trusted proxy docs готовы.
13. Header denylist реализован.
14. Raw sensitive values не попадают в safe output.
15. Packagist metadata заполнена.
16. Git tag `v1.0.0` создан.

## 40. Рекомендуемый `composer.json`

```json
{
  "name": "globus-studio/fingerprint",
  "description": "Server-side PHP fingerprinting library for security, risk scoring, and privacy-aware client identification.",
  "type": "library",
  "license": "MIT",
  "authors": [
    {
      "name": "Yevhen Leonidov",
      "homepage": "https://globus.studio",
      "role": "Developer"
    }
  ],
  "require": {
    "php": ">=8.3 <9.0",
    "ext-json": "*",
    "ext-hash": "*",
    "ext-filter": "*"
  },
  "require-dev": {
    "phpunit/phpunit": "^11.0 || ^12.0",
    "phpstan/phpstan": "^2.0",
    "friendsofphp/php-cs-fixer": "^3.0"
  },
  "suggest": {
    "ext-intl": "Improves Unicode and locale normalization.",
    "ext-sodium": "Enables optional Sodium hashing.",
    "psr/http-message": "Required for PSR-7 request integration.",
    "psr/log": "Allows diagnostic logging."
  },
  "autoload": {
    "psr-4": {
      "GlobusStudio\\Fingerprint\\": "src/"
    }
  },
  "autoload-dev": {
    "psr-4": {
      "GlobusStudio\\Fingerprint\\Tests\\": "tests/"
    }
  },
  "scripts": {
    "test": "phpunit",
    "analyse": "phpstan analyse",
    "cs": "php-cs-fixer fix --dry-run --diff",
    "cs:fix": "php-cs-fixer fix"
  },
  "keywords": [
    "fingerprint",
    "device-fingerprint",
    "browser-fingerprint",
    "php",
    "security",
    "fraud-detection",
    "risk-scoring",
    "psr-7",
    "laravel",
    "symfony"
  ]
}
```

## 41. Рекомендуемые первые задачи для реализации

1. Создать Composer skeleton.
2. Добавить namespace `GlobusStudio\\Fingerprint`.
3. Реализовать `RequestContext`, `HeaderBag`, `ServerBag`.
4. Реализовать `HeaderNormalizer`.
5. Реализовать `IpNormalizer` и CIDR utilities.
6. Реализовать `Signal`, `SignalSet`, `SignalCollectorInterface`.
7. Реализовать `HeaderSignalCollector`.
8. Реализовать `NetworkSignalCollector`.
9. Реализовать `CanonicalJsonEncoder`.
10. Реализовать `HmacSha256Hasher`.
11. Реализовать `FingerprintBuilder`.
12. Покрыть core unit tests.
13. Добавить fixtures для Nginx/Apache/IIS.
14. Добавить README quick start.
15. Настроить CI.

## 42. Критерии качества библиотеки

Библиотека будет считаться качественной, если она:

1. Честно объясняет ограничения fingerprinting.
2. Не собирает лишние чувствительные данные по умолчанию.
3. Дает стабильный output для одинаковых входов.
4. Не ломается на разных серверах и SAPI.
5. Корректно работает за reverse proxy.
6. Имеет понятную систему весов и confidence.
7. Позволяет сравнивать отпечатки, а не только проверять exact hash.
8. Имеет сильные тесты и golden fixtures.
9. Документирована для production deployment.
10. Готова к Packagist и SemVer.
