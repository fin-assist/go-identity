# go-identity

Общая проверка идентичности для пяти Go-сервисов «Понятные финансы»: JWT пользователя, projected ServiceAccount tokens k3s и короткие сервисные JWT стенда. [FIN-119](https://finassist.youtrack.cloud/issue/FIN-119). Источник правил — [grpc-api.md](https://github.com/fin-assist/contracts/blob/main/docs/grpc-api.md), разделы 3–5 и 7.1, и «Архитектура» → «Аутентификация» в Confluence PF.

Библиотека проверяет идентичность и таблицу вызывающих. Проверка tombstone, доступ к объекту, идемпотентность, валидация тела и бизнес-правила остаются в сервисе. БД и миграций здесь нет. Ни токены, ни ключи, ни ошибки транспорта библиотека не пишет в логи.

## Раскладка

| Файл | Назначение |
|---|---|
| `verify.go` | JWT пользователя (Ed25519 / ES256), ServiceAccount (RS256 / ES256 / Ed25519), стенд (Ed25519) |
| `keys.go`, `providers.go` | JWKS, общий кэш, gRPC `GetSigningKeys`, HTTPS API-сервера |
| `tokens.go` | projected-файл и подпись короткого JWT ключом стенда |
| `context.go`, `grpc.go`, `http.go` | контекст, таблица доступа, серверные и клиентские интерцепторы, HTTP-middleware |
| `metrics.go` | метрика отказов без пользовательских идентификаторов |
| `*_test.go` | unit, TLS/файловые интеграции, usage HTTP → gRPC и ServiceAccount → gRPC на bufconn |
| `docs/releasing.md`, `CHANGELOG.md` | версии и совместимость |

## Внедрение

### 1. Зависимость и настройки

После выпуска владельцем: `go get github.com/fin-assist/go-identity@vX.Y.Z`. Тегов реализации пока нет; временный `replace` допустим только локально, в PR сервиса не попадает. Версии — [docs/releasing.md](docs/releasing.md). Контракты закреплены на `gen/go/v0.4.0`; API контрактов библиотека не меняет.

В `internal/app` сервис явно передаёт часы (`time.Now` в сборке), реестр Prometheus, issuer/audience пользователя и issuer кластера. Значения `iss`/`aud` пользовательского токена должны совпадать с конфигурацией выпускающего `user`: библиотека не придумывает их и не извлекает из непроверенного токена. Не используйте один набор ключей для пользовательских и сервисных токенов.

Сервис выбирает режим по своей проверенной конфигурации: prod — только Kubernetes; stage/dev — либо Kubernetes, либо конструкторы `NewStageSource` / `NewStageVerifier`. Оба файловых конструктора требуют явный `env` и отказывают при `prod`, пустом или неизвестном окружении. Отказ конструктора — ошибка старта, перехода на небезопасный режим нет.

Новые зависимости: `golang-jwt/jwt/v5` — разбор и проверка JWT (в stdlib нет JWT), `contracts/gen/go` — сгенерированный клиент и `finerr`, `grpc` / `protobuf` — транспорт и проверка поля `user_id`, `prometheus/client_golang` — реестр сервиса. Криптография, JWK, файлы и HTTP — стандартная библиотека. Глобальных часов/логгера/реестра/настроек библиотека не берёт.

### 2. Сервисный токен клиента

Прод: смонтируйте отдельный projected volume, `serviceAccountToken.audience: finassist-internal`, `expirationSeconds: 3600`. У каждого сервиса свой ServiceAccount в namespace `finassist`.

```go
source, err := identity.NewProjectedSource("/var/run/secrets/finassist/token")
if err != nil { return err }
// Добавьте к остальным опциям соединения, которым владеет сервис:
clientOptions := []grpc.DialOption{
    grpc.WithChainUnaryInterceptor(identity.UnaryClient(source)),
    grpc.WithChainStreamInterceptor(identity.StreamClient(source)),
}
```

Файл проверяется при каждом открытии RPC: кэш — по mtime, размеру и идентичности inode. Атомарная замена symlink kubelet распознаётся даже при одинаковом mtime. Исчезнувший/нечитаемый файл не возвращает старый токен. Размер токена ограничен 16 KiB. Клиент заменяет `x-service-authorization` и `authorization`, сохраняя остальные outgoing metadata; пользовательский токен пробрасывает только из проверенного контекста этой библиотеки, байт в байт.

Стенд: передайте `StageOptions{KeyFile, Caller, Issuer, Clock, TTL}` в `NewStageSource(env, options)`. Файл — PKCS#8 PEM Ed25519; права `0600`, отдельный ключ каждому сервису, путь берётся из конфигурации сервиса. TTL по умолчанию 1 минута, предел 5 минут; JWT обновляется перед последними 20% срока. `kid=sub=Caller`, `aud=finassist-internal`. Ключ загружается при старте; для ротации приватного ключа перезапустите сервис. Это реальные подписанные токены, не dev-заглушка.

### 3. Источники JWKS и bootstrap

Для user JWT: `NewKeyCache(UserKeys{Client: userClient}, clock, 10*time.Minute)`. `userClient` — сгенерированный `UserInternalServiceClient` на соединении с сервисным интерцептором из шага 2. `GetSigningKeys` в таблице — `NoUser` для всех пяти сервисов, но всё равно требует сервисный токен. Сам `user` берёт собственные публичные ключи через локальную реализацию `JWKSProvider`, чтобы не создавать зависимость старта от собственного RPC.

Прод: создайте `HTTPKeys` через `NewHTTPKeys(client, "https://kubernetes.default.svc/openid/v1/jwks", apiTokenSource)`; используйте доверенный cluster CA (`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`) в `http.Transport`, проверку TLS не выключайте. `apiTokenSource` — отдельный `NewProjectedSource("/var/run/secrets/kubernetes.io/serviceaccount/token")` со штатным токеном пода для audience API-сервера, **не** `finassist-internal`. На каждом fetch заголовок `Authorization` берётся заново из этого источника: ротация файла учитывается. Без него защищённый endpoint ответит 401/403. Клиент и transport принадлежат сервису. Redirect запрещён; ответ — только 200, не более 1 MiB. `NewKeyCache(provider, clock, time.Hour)` → `NewKubernetesVerifier(cache, VerifyOptions{Issuer: "https://kubernetes.default.svc.cluster.local", Audience: "finassist-internal", Clock: clock, Observer: metrics}, "finassist")`. Помимо подписи/`exp`/`iss`/`aud` проверяются namespace и точное соответствие `sub=system:serviceaccount:<namespace>:<name>` подписанным Kubernetes claims. TokenReview не вызывается.

На всех серверах k3s зафиксируйте `service-account-issuer=https://kubernetes.default.svc.cluster.local`. Выдайте ServiceAccount сервисов право `system:service-account-issuer-discovery` по инфраструктурной процедуре; библиотека доступ не создаёт. HTTP-запрос должен предъявлять штатный API-server-audience токен этого ServiceAccount: одна RBAC-привязка без заголовка не авторизует запрос. При отключённом automount явно смонтируйте и такой токен, и CA отдельным volume. Анонимный доступ не требуется.

Стенд: `NewStageVerifier(env, options, map[string]ed25519.PublicKey{...})`, issuer общий с источником, audience `finassist-internal`. Карта индексируется **именем сервиса**: ключ одного сервиса не удостоверяет другой `sub`. Карта копируется; для ротации набора ключей пересоздайте verifier/перезапустите получателей. Ротация без простоя с двумя ключами одного сервиса пока не поддерживается: согласуйте короткое окно развёртывания, истекающие токены повторяются вызывающим по правилам метода. Не используйте один приватный ключ у разных сервисов.

JWKS загружается лениво на первом запросе или в `cache.Run(ctx)` — это явное задание сервиса, без скрытых горутин. Сервис запускает и останавливает оба кэша своим lifecycle. Каждый fetch ограничен 5 с; уже начавшийся общий fetch отвязан от отмены отдельного запроса. Отменённый до захвата gate запрос не тратит минутный слот; ожидающий gate прекращает ждать по своему контексту. Отмена запроса не отменяет общий результат для остальных вызовов. Известный ключ обслуживается локально; неизвестный `kid` обновляет набор, но не чаще раза в минуту, включая ошибки и параллельные запросы. Набор публикуется целиком; неудачная загрузка не затирает последний успешный. Просроченный снимок после неудачного refresh не используется: запрос отклоняется, а не доверяет ключам бесконечно. Параметр кэша — максимальный возраст снимка: 10 минут для пользователя, час для Kubernetes (минимально допустимы 2 минуты). `Run` проверяет необходимость обновления каждую минуту и начинает его уже на половине максимального возраста — на 5-й/30-й минуте. После ошибки повторяет через минуту, пока предыдущий снимок ещё действует. Это опережение относительно номинальных 10 минут/часа даёт запас на сбой источника, не продлевая доверие старому снимку. `Run` возвращает ошибку контекста при остановке, завершив уже начатый fetch максимум за 5 с.

Ротация JWT пользователя: сначала опубликуйте старый и новый ключи, выдержите как минимум минуту для ограничителя неизвестного `kid`, затем начните подписывать новым. Старый ключ удалите после истечения всех ранее выданных access-токенов и запаса на развёртывание. JWK — публичные OKP Ed25519, EC P-256 или RSA 2048–4096 бит, максимум 64 ключа с уникальными `kid`; поддержаны `use=sig` и `key_ops=verify`.

### 4. Пользовательский verifier и таблица метода

```go
users, err := identity.NewUserVerifier(userKeys, identity.VerifyOptions{
    Issuer: cfg.UserIssuer, Audience: cfg.UserAudience,
    Clock: clock, Observer: metrics,
})
if err != nil { return err }
access, err := identity.NewServer(identity.AccessTable{
    analyticsv1.AnalyticsService_GetAnalytics_FullMethodName: {
        "bank-bff": identity.User,
        "assistant": identity.System,
    },
    analyticsv1.AnalyticsService_ListPeriods_FullMethodName: {
        "bank-bff": identity.User,
        "assistant": identity.System,
    },
}, services, users, metrics)
if err != nil { return err }
server := grpc.NewServer(
    grpc.ChainUnaryInterceptor(access.Unary() /* затем tombstone и остальная цепочка */),
    grpc.ChainStreamInterceptor(access.Stream() /* затем tombstone и остальная цепочка */),
)
```

Это пример таблицы `analytics`, не общая таблица всех сервисов. Используйте сгенерированные `*_FullMethodName`, отдельную строку для каждого RPC, без wildcard. Карта копируется. Отсутствующая строка/чужой вызывающий — голый `PERMISSION_DENIED`, без `ErrorInfo`; отсутствующий/невалидный сервисный токен — голый `UNAUTHENTICATED`. Пользовательский токен — `finerr.InvalidToken()` (включая просроченный access JWT; `TOKEN_EXPIRED` относится к регистрации).

- `User`: `identity.UserID(ctx)` — только проверенный `sub`. У смешанного контракта `user_id` может быть пустым или равным `sub`; чужое значение блокируется до обработчика. Для методов только пользовательской модели `user_id` в контракте нет.
- `System`: `identity.Caller(ctx)` — проверенный сервис, `identity.SystemUserID(ctx, req.GetUserId())` проверяет модель и обязательность поля. Обработчик обязан проверять ошибку помощника перед доступом к данным. Для системного контекста `UserID` отсутствует, даже если прислали пользовательский заголовок.
- `NoUser`: auth/JWKS RPC без access-токена; **не** анонимный сервисный доступ. Условные требования (например, ASSISTANT-документ согласия) остаются в обработчике по контракту.

Stream проверяет токены при открытии, каждый принятый `user_id` — при `RecvMsg`. Уже открытый поток не прерывается в момент истечения access-токена. Обработчик не игнорирует ошибки `RecvMsg`. Tombstone подключается после идентичности и проверяет пользователя по правилам FIN-110. Библиотека не заменяет таблицу NetworkPolicy.

В шаблоне сервиса уже есть интерфейсы `VerifyUser`/`VerifyService`: verifier библиотеки реализуют их. При переходе на `identity.Server` не оставляйте вторую цепочку аутентификации; контекст шаблона и контекст библиотеки различаются, поэтому обработчики/tombstone явно переводятся на `UserID` / `Caller` / `SystemUserID` либо адаптируются. FIN-119 поставляет библиотеку и инструкцию; подключение в конкретные сервисы выполняется их PR после тега.

### 5. HTTP bank-bff

`NewHTTP(users, writeContractError)` → `auth.Middleware(protectedHandler)`. Регистрируйте публичные auth-маршруты отдельно. Проверка `iat`/`nbf` допускает расхождение часов до 5 секунд; `exp` остаётся строгой границей без продления (для всех трёх verifier). Часы узлов всё равно синхронизируются инфраструктурой. Middleware проверяет единственный `Authorization: Bearer …` (scheme без учёта регистра), подпись, срок, issuer/audience, непустой `sub`. Несколько заголовков, пустой и чрезмерный токен отклоняются до handler. Ошибка передаётся сервисному обработчику как `finerr.InvalidToken()`; он строит 401 и JSON строго по OpenAPI. Порядок maintenance/client-version middleware должен сохранить приоритет ошибок из `docs/api.md`.

Обработчик использует `r.Context()` в сгенерированном gRPC-клиенте с клиентскими интерцепторами шага 2. Исходный пользовательский токен попадает в `authorization` автоматически; повторный разбор JWT в сервисе обязателен. Не копируйте непроверенный HTTP-заголовок в outgoing metadata вручную — клиент его заменит.

### 6. Наблюдаемость, маскирование и проверки

`NewMetrics(serviceRegistry)` → передайте один экземпляр в verifier и `Server` как `Observer`. Метрика `finassist_identity_rejected_total{kind,reason}`: kind `user|service|access`; reason `invalid|expired|signature|audience|issuer|key_unavailable|forbidden|user_id`. Вызовы вне таблицы и несовпавший `user_id` — `kind=access`. Идентификаторов и произвольных строк в метках нет. Пример алерта на чужого вызывающего: `sum(increase(finassist_identity_rejected_total{kind="access",reason="forbidden"}[5m])) > 0`; отдельно наблюдайте рост `key_unavailable` и `signature`. Алерты создаёт сервис в своей инфраструктуре, библиотека их не отправляет.

Перед журналированием metadata — `identity.MaskMetadata(md)`: независимая копия с маской для `authorization`, `x-service-authorization`, `idempotency-key` и имён с `token`. Сам интерцептор не журналирует запросы. Маскирование тел protobuf `*token*` и HTTP access-логов остаётся обязанностью логгера сервиса; не журналируйте исходный `r.Header`/`metadata.MD`.

Чек-лист нового метода:

1. Контракт уже выпущен в `contracts/gen/go`, caller/model соответствуют `docs/grpc-api.md`.
2. Добавлены точная строка таблицы и NetworkPolicy; выбран `User`, `System` или `NoUser` для каждого вызывающего.
3. Обработчик берёт пользователя из `sub` либо проверяет `SystemUserID`; проверка tombstone и владельца объекта покрыта тестами сервиса.
4. Добавлены негативные тесты: чужой/отсутствующий вызывающий, невалидный токен, чужой `user_id`, отсутствующая строка, для stream — ошибки `RecvMsg`.
5. Логирование маскирует metadata и поля токенов; метрики/алерты подключены к реестру сервиса.

## Проверки

```bash
make test    # vet, go test -race, тесты скриптов и CHANGELOG
make lint
make cover   # покрытие изменённых строк относительно origin/main
make api     # gorelease относительно последнего тега
```

В окружении агента каждый запуск ограничивается временем процесса. Интеграции используют настоящий TLS HTTP, файловую систему и gRPC bufconn, без внешних сервисов; PostgreSQL для этой библиотеки не нужен. Usage-тесты вызывают сгенерированные API-клиенты и проверяют статус, `ErrorInfo`, metadata и недостижимость обработчика при отказе. CI выполняет те же проверки, публикует покрытие изменённых строк (цель ≥80%) и проверяет совместимость API. Примеры `Example…` компилируются вместе с тестами.
