# go-identity

Общая проверка идентичности для пяти Go-сервисов «Понятные финансы»: JWT пользователя, projected ServiceAccount tokens k3s и короткие сервисные JWT стенда. [FIN-119](https://finassist.youtrack.cloud/issue/FIN-119). Источник правил — [grpc-api.md](https://github.com/fin-assist/contracts/blob/main/docs/grpc-api.md), разделы 3–5 и 7.1, и «Архитектура» → «Аутентификация» в Confluence PF.

Библиотека проверяет идентичность и таблицу вызывающих. Проверка tombstone, доступ к объекту, идемпотентность, валидация тела и бизнес-правила остаются в сервисе. БД и миграций здесь нет. Ни токены, ни ключи, ни ошибки транспорта библиотека не пишет в логи.

## Автоматизация обновлений зависимостей

[Политика Renovate](docs/renovate-policy.md) (FIN-211): одна актуальная release/main, автомерж полностью ботских PR после обязательного CI, один повтор красного CI и закрытие с явным повтором через Dependency Dashboard. AndroidX/Compose остаются на ручной проверке. Исходные группировки, ограничения версий и расписания — `renovate-base.json`; generated target и quarantine — ветка `renovate-policy`. Активация требует отдельного токена и строгой защиты веток; по умолчанию выключена.

## Раскладка

| Файл | Назначение |
|---|---|
| `verify.go` | JWT пользователя (Ed25519 / ES256), ServiceAccount (RS256 / ES256 / Ed25519), стенд (Ed25519) |
| `keys.go`, `providers.go` | JWKS, общий кэш, gRPC `GetSigningKeys`, HTTPS API-сервера |
| `tokens.go` | projected-файл и подпись короткого JWT ключом стенда |
| `context.go`, `grpc.go`, `http.go` | контекст, таблица доступа, серверные и клиентские интерцепторы, HTTP-middleware |
| `metrics.go` | метрики отказов и пропущенных JWK без пользовательских идентификаторов |
| `assembly.go` | готовая сборка для сервиса: `NewAssembly` (prod — Kubernetes, stage — ключи из файлов, ключи пользователя, метрики, `Run`) |
| `*_test.go` | unit, TLS/файловые интеграции, usage HTTP → gRPC и ServiceAccount → gRPC на bufconn |
| `docs/releasing.md`, `CHANGELOG.md` | версии и совместимость |

## Внедрение

### 0. Готовая сборка: `NewAssembly` (FIN-273)

Сервис вызывает один конструктор вместо собственной копии сборки в `internal/app`. Шаги 1–3 ниже описывают детали, которые `NewAssembly` уже выполняет; отдельные конструкторы остаются для особых случаев.

`NewAssembly(AssemblyOptions)` строит:

- в `Env: "prod"` — проверку ServiceAccount Kubernetes: JWKS API-сервера по HTTPS с доверием только к `CAFile` (прокси из окружения не используется), отдельный API-токен пода для запроса JWKS, кэш на час, проверку namespace и `sub`; исходящий токен — projected-файл `finassist-internal`;
- в `Env: "stage"` — короткие JWT стенда: исходящие подписываются собственным PKCS#8 Ed25519 ключом (`kid` = `sub` = имя сервиса, TTL 1 минута), входящие проверяются по JWKS ключей сервисов стенда (только OKP Ed25519, `kid` — имя сервиса; неподдерживаемый или чужой по форме ключ отклоняет весь файл);
- в обоих — проверку access JWT пользователя по ключам `user.GetSigningKeys` (кэш на 10 минут) и метрики `finassist_identity_rejected_total`, `finassist_identity_jwks_skipped_keys` (шаг 6).

`dev`, пустое и любое другое значение `Env` отклоняются: `AUTH_MODE=insecure-dev` с dev-токенами go-grpc остаётся кодом сервиса и допустим только при `ENV=dev`. Файлы стенда, заданные в `prod`, — ошибка старта. Отказ конструктора не оставляет зарегистрированных метрик и открытых соединений; перехода на более слабый режим нет. Библиотека не читает переменные окружения: сервис переносит свою конфигурацию в поля опций.

| Переменная сервиса | Поле `AssemblyOptions` | По умолчанию |
|---|---|---|
| `ENV` | `Env` | — (`prod` или `stage`) |
| `SERVICE_NAME` | `Service` | — |
| `AUTH_USER_ISSUER`, `AUTH_USER_AUDIENCE` | `UserIssuer`, `UserAudience` | — (обязательны) |
| `SERVICE_TOKEN_FILE` | `Kubernetes.TokenFile` | — (обязателен в prod, отличается от API-токена) |
| `AUTH_KUBERNETES_ISSUER` | `Kubernetes.Issuer` | `https://kubernetes.default.svc.cluster.local` |
| `AUTH_KUBERNETES_JWKS_URL` | `Kubernetes.JWKSURL` | `https://kubernetes.default.svc/openid/v1/jwks` |
| `AUTH_KUBERNETES_CA_FILE` | `Kubernetes.CAFile` | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` |
| `AUTH_KUBERNETES_API_TOKEN_FILE` | `Kubernetes.APITokenFile` | `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| `AUTH_KUBERNETES_NAMESPACE` | `Kubernetes.Namespace` | `finassist` |
| `AUTH_STAGE_ISSUER` | `Stage.Issuer` | — (обязателен в stage) |
| `AUTH_STAGE_SIGNING_KEY_FILE` | `Stage.SigningKeyFile` | — (обязателен в stage) |
| `AUTH_STAGE_PUBLIC_KEYS_FILE` | `Stage.PublicKeysFile` | — (обязателен в stage) |

Пустое поле `Kubernetes` получает значение по умолчанию, поэтому сервис может передавать значения своих переменных как есть. Имена переменных — рекомендация для шаблона и сервисов (решение владельца FIN-273: набор `AUTH_*` assistant); `user` переходит на них отдельной задачей вместе с манифестами.

```go
id, err := identity.NewAssembly(identity.AssemblyOptions{
    Env: string(cfg.Env), Service: cfg.Service,
    UserIssuer: cfg.Auth.UserIssuer, UserAudience: cfg.Auth.UserAudience,
    DialUser: func(tokens identity.TokenSource) (*grpc.ClientConn, error) {
        return client.Dial(cfg.Peers["user"], client.Options{
            Peer: "user", Tokens: tokens,
            Retry: []string{"finassist.user.v1.UserInternalService/GetSigningKeys"},
        })
    },
    Kubernetes: identity.KubernetesOptions{TokenFile: cfg.ServiceTokenFile, Issuer: cfg.Auth.KubernetesIssuer /* … */},
    Stage:      identity.StageKeyFiles{ /* только при ENV=stage */ },
    Clock:      time.Now, Registerer: registry,
})
if err != nil { return err }
deps := server.Deps{Services: id, Users: id /* Logger, Metrics, Policy, Tombstones */}
jobs := []worker.Job{{Name: "identity-keys", Run: id.Run}}
// Исходящие соединения: client.Options{Tokens: id}. При остановке, после завершения Run: id.Close().
```

- `*Assembly` реализует `VerifyService`, `VerifyUser` и `Token` — интерфейсы `server.ServiceVerifier`, `server.UserVerifier`, `client.TokenSource` из go-grpc, а также `UserChecker` для `NewHTTP` в bank-bff. Таблицу вызывающих со сборкой проверяет цепочка go-grpc (`server.Policy`), и отказы доступа считает она же; `identity.NewServer` со сборкой не используйте: её `Metrics` внутренний, и метрика `finassist_identity_rejected_total{kind="access"}` из шага 6 не заполнится. Вторую цепочку аутентификации не ставьте.
- `DialUser` вызывается один раз в конструкторе с исходящим источником токенов сборки; соединение принадлежит сборке и закрывается в `Close`. Повторы — только `GetSigningKeys`. Сам `user` вместо `DialUser` передаёт `UserKeys` — локальный `JWKSProvider` своих публичных ключей, без вызова собственного RPC. Задаётся ровно одно из двух.
- Конструктор ключей не загружает и горутин не запускает. `Run(ctx)` — задание сервиса: обновляет кэш ключей пользователя и, в prod, Kubernetes по правилам шага 3 и возвращает `ctx.Err()` после остановки всех циклов. До запуска `Run` ключи загружаются лениво на первом запросе.
- Часы и реестр обязательны; логгер не нужен — библиотека ничего не журналирует, сбои ключей видны по `finassist_identity_rejected_total{reason="key_unavailable"}`.
- Стенд: ротация ключа сервиса требует перезапуска (файлы читаются при старте), см. шаг 3.

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

JWKS загружается лениво на первом запросе или в `cache.Run(ctx)` — это явное задание сервиса, без скрытых горутин. Сервис запускает и останавливает оба кэша своим lifecycle. Каждый fetch ограничен 5 с; уже начавшийся общий fetch отвязан от отмены отдельного запроса. Отменённый до захвата gate запрос не тратит минутный слот; ожидающий gate прекращает ждать по своему контексту. Отмена запроса не отменяет общий результат для остальных вызовов. Известный ключ обслуживается локально; неизвестный `kid` обновляет набор, но не чаще раза в минуту, включая ошибки и параллельные запросы. Набор публикуется целиком; неудачная загрузка не затирает последний успешный. Просроченный снимок после неудачного refresh не используется: запрос отклоняется, а не доверяет ключам бесконечно. Такой отказ — не вердикт по токену ([FIN-293](https://finassist.youtrack.cloud/issue/FIN-293)): когда свежего снимка нет (старт при недоступном источнике или с невалидным набором, снимок старше максимального возраста, а обновление не удалось или упёрлось в минутный лимит), `VerifyUser` и `VerifyService` возвращают голый `UNAVAILABLE` без `ErrorInfo`, а `Server` и HTTP-middleware передают его дальше без замены на `INVALID_TOKEN`/`UNAUTHENTICATED`. `bank-bff` отвечает на него 500 `INTERNAL_ERROR` (неизвестная `finerr.ToREST` ошибка), и клиент не выходит из аккаунта из-за сбоя `user` или API-сервера. Отменённый или истёкший контекст запроса — голый `CANCELED` / `DEADLINE_EXCEEDED`. Неизвестный `kid` при свежем снимке остаётся невалидным токеном, даже если вызванное им обновление не удалось: произвольный `kid` не превращает сбой источника в `UNAVAILABLE`. Параметр кэша — максимальный возраст снимка: 10 минут для пользователя, час для Kubernetes (минимально допустимы 2 минуты). `Run` проверяет необходимость обновления каждые 30 секунд и начинает его уже на половине максимального возраста — на 5-й/30-й минуте. После ошибки повтор разрешён не раньше чем через минуту и выполняется на ближайшем подходящем тике (обычно через 60–90 секунд, без учёта задержек планировщика и ожидания gate). Частота сетевых запросов остаётся не выше раза в минуту. Это опережение относительно номинальных 10 минут/часа даёт запас на сбой источника, не продлевая доверие старому снимку. `Run` возвращает ошибку контекста при остановке, завершив уже начатый fetch максимум за 5 с.

Ротация JWT пользователя: сначала опубликуйте старый и новый ключи, выдержите как минимум минуту для ограничителя неизвестного `kid`, затем начните подписывать новым. Перекрытие обязательно: сервис, у которого снимок ещё свежий, а источник ключей недоступен, считает токен с неопубликованным для него `kid` невалидным (`INVALID_TOKEN`), а не временным сбоем. Чтобы исключить этот случай и при сбое `user`, публикуйте новый ключ заранее: не меньше чем за 10 минут (максимальный возраст снимка) плюс время раскатки нового набора на все реплики `user` и время загрузки (до 5 с; возраст снимка отсчитывается от завершения загрузки). Старый ключ удалите после истечения всех ранее выданных access-токенов и запаса на развёртывание. JWK — публичные OKP Ed25519, EC P-256 или RSA 2048–4096 бит, максимум 64 ключа с уникальными `kid`; поддержаны `use=sig` и `key_ops=verify`.

Состав набора JWKS ([FIN-311](https://finassist.youtrack.cloud/issue/FIN-311)). Поддерживаются OKP Ed25519 (`alg` пусто/`EdDSA`), EC P-256 (`alg` пусто/`ES256`) и RSA 2048–4096 бит (`alg` пусто/`RS256`). JWK неподдерживаемого типа или назначения пропускается, а не отклоняет весь снимок (RFC 7517, раздел 5): неизвестный `kty`, `crv` или `alg`, `use` не `sig`, `key_ops` без `verify`, RSA длиннее 4096 бит. Токен с `kid` пропущенного ключа получает тот же исход, что и токен с неизвестным `kid`, и никогда не принимается. Весь набор по-прежнему отклоняется (снимок не обновляется, действует прежний в пределах своего возраста) при явно повреждённых данных: невалидный JSON или данные после него, больше 64 ключей или 1 MiB, ключ без `kty` (обязателен по RFC 7517, раздел 4.1), ключ без `kid` или с `kid` длиннее 256 байт, повтор `kid` — **во всём наборе, включая пропущенные ключи**, битый base64, неверная длина или точка не на кривой у поддержанного типа, RSA короче 2048 бит или с негодной экспонентой при `alg` пусто/`RS256`, отсутствие поддержанных ключей после фильтрации.

Это важно для ротации ключа ServiceAccount: Kubernetes публикует в `/openid/v1/jwks` все ключи из `--service-account-key-file` (RSA с `RS256`, ECDSA P-256/P-384/P-521 с `ES256`/`ES384`/`ES512`, `use=sig`). Добавленный ключ EC P-384 или RSA 8192 больше не отключает проверку токенов действующего RSA-ключа, но **подписывать токены ключом неподдерживаемого типа нельзя**: они будут отклонены. Перед переводом подписи на новый ключ убедитесь, что он поддержан и `finassist_identity_jwks_skipped_keys` для него не растёт (шаг 6). Чтобы видеть пропущенные ключи, создавайте кэш через `NewObservedKeyCache(provider, clock, interval, kind, metrics)` вместо `NewKeyCache`: `kind` — `user` для ключей пользователя или `service` для Kubernetes; остальные параметры и поведение те же.

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

Это пример таблицы `analytics`, не общая таблица всех сервисов. Используйте сгенерированные `*_FullMethodName`, отдельную строку для каждого RPC, без wildcard. Карта копируется. Отсутствующая строка/чужой вызывающий — голый `PERMISSION_DENIED`, без `ErrorInfo`; отсутствующий/невалидный сервисный токен — голый `UNAUTHENTICATED`. Пользовательский токен — `finerr.InvalidToken()` (включая просроченный access JWT; `TOKEN_EXPIRED` относится к регистрации). Недоступные ключи проверки (пользовательские или кластера) — голый `UNAVAILABLE`: токен не проверен, повтор безопасен (шаг 3).

- `User`: `identity.UserID(ctx)` — только проверенный `sub`. У смешанного контракта `user_id` может быть пустым или равным `sub`; чужое значение блокируется до обработчика. Для методов только пользовательской модели `user_id` в контракте нет.
- `System`: `identity.Caller(ctx)` — проверенный сервис, `identity.SystemUserID(ctx, req.GetUserId())` проверяет модель и обязательность поля. Обработчик обязан проверять ошибку помощника перед доступом к данным. Для системного контекста `UserID` отсутствует, даже если прислали пользовательский заголовок.
- `NoUser`: auth/JWKS RPC без access-токена; **не** анонимный сервисный доступ. Условные требования (например, ASSISTANT-документ согласия) остаются в обработчике по контракту.

Stream проверяет токены при открытии, каждый принятый `user_id` — при `RecvMsg`. Уже открытый поток не прерывается в момент истечения access-токена. Обработчик не игнорирует ошибки `RecvMsg`. Tombstone подключается после идентичности и проверяет пользователя по правилам FIN-110. Библиотека не заменяет таблицу NetworkPolicy.

В шаблоне сервиса уже есть интерфейсы `VerifyUser`/`VerifyService`: verifier библиотеки реализуют их. При переходе на `identity.Server` не оставляйте вторую цепочку аутентификации; контекст шаблона и контекст библиотеки различаются, поэтому обработчики/tombstone явно переводятся на `UserID` / `Caller` / `SystemUserID` либо адаптируются. FIN-119 поставляет библиотеку и инструкцию; подключение в конкретные сервисы выполняется их PR после тега.

### 5. HTTP bank-bff

`NewHTTP(users, writeContractError)` → `auth.Middleware(protectedHandler)`. Регистрируйте публичные auth-маршруты отдельно. Проверка `iat`/`nbf` допускает расхождение часов до 5 секунд; `exp` остаётся строгой границей без продления (для всех трёх verifier). Часы узлов всё равно синхронизируются инфраструктурой. Middleware проверяет единственный `Authorization: Bearer …` (scheme без учёта регистра), подпись, срок, issuer/audience, непустой `sub`. Несколько заголовков, пустой и чрезмерный токен отклоняются до handler. Ошибка передаётся сервисному обработчику как `finerr.InvalidToken()`; он строит 401 и JSON строго по OpenAPI. Если токен нельзя проверить (нет свежих ключей, контекст запроса завершён), обработчик получает голый `UNAVAILABLE` / `CANCELED` / `DEADLINE_EXCEEDED`: `finerr.ToREST` его не переводит, обработчик отвечает 500 `INTERNAL_ERROR`, а не 401. Порядок maintenance/client-version middleware должен сохранить приоритет ошибок из `docs/api.md`.

Обработчик использует `r.Context()` в сгенерированном gRPC-клиенте с клиентскими интерцепторами шага 2. Исходный пользовательский токен попадает в `authorization` автоматически; повторный разбор JWT в сервисе обязателен. Не копируйте непроверенный HTTP-заголовок в outgoing metadata вручную — клиент его заменит.

### 6. Наблюдаемость, маскирование и проверки

`NewMetrics(serviceRegistry)` → передайте один экземпляр в verifier и `Server` как `Observer`. Метрика `finassist_identity_rejected_total{kind,reason}`: kind `user|service|access`; reason `invalid|expired|signature|audience|issuer|key_unavailable|unknown_key|forbidden|user_id`. `key_unavailable` — нет свежего снимка ключей (сбой источника, токен не проверялся); `unknown_key` — `kid` отсутствует в свежем снимке (подделка или подпись ещё не опубликованным ключом при ротации). Отменённый вызывающим запрос отказом не считается. Вызовы вне таблицы и несовпавший `user_id` — `kind=access`. Идентификаторов и произвольных строк в метках нет. Пример алерта на чужого вызывающего: `sum(increase(finassist_identity_rejected_total{kind="access",reason="forbidden"}[5m])) > 0`; отдельно наблюдайте рост `key_unavailable` (сбой источника ключей), `unknown_key` (ротация или подбор `kid`) и `signature`. Алерты создаёт сервис в своей инфраструктуре, библиотека их не отправляет.

Метрика `finassist_identity_jwks_skipped_keys{kind,reason}` (gauge, при `NewObservedKeyCache`) — число JWK, пропущенных как неподдерживаемые, в **текущем** снимке: kind `user|service`; reason `kty|crv|alg|use|key_ops|size` (`size` — RSA длиннее 4096 бит). Каждый установленный снимок задаёт все шесть значений, включая нули; неудачная загрузка их не меняет. Выбран gauge, а не счётчик за refresh: значение не зависит от частоты обновлений и числа подов и само падает до нуля, когда ключ убран из набора, поэтому алерт прямо отвечает «в наборе есть ключ, которым нельзя подписывать». `kid` и произвольных строк в метках нет. Пример алерта: `max by (kind, reason) (finassist_identity_jwks_skipped_keys) > 0` в течение 15 минут — предупреждение до ротации подписи на неподдерживаемый ключ; срочный сигнал о том, что подпись уже перешла, — рост `finassist_identity_rejected_total{kind="service"}` (токен с `kid` пропущенного ключа учитывается так же, как с неизвестным `kid`).

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
make cover   # независимые пороги statements для unit/integration/API
make api     # gorelease относительно последнего тега
```

В окружении агента каждый запуск ограничивается временем процесса. Интеграции используют настоящий TLS HTTP, файловую систему и gRPC bufconn, без внешних сервисов; PostgreSQL для этой библиотеки не нужен. Usage-тесты вызывают сгенерированные API-клиенты и проверяют статус, `ErrorInfo`, metadata и недостижимость обработчика при отказе. CI выполняет те же проверки, проверяет три независимых порога statements ≥80% и проверяет совместимость API. Примеры `Example…` компилируются вместе с тестами.

### Покрытие statements (FIN-243)

`go-test-coverage/v2` закреплён на v2.20.1. Unit, integration и consumer API должны **каждый** покрывать не менее
80% statements production-пакетов, с одним знаменателем для всех трёх наборов. Список `-coverpkg` берётся из
`go list -race ./...`; по явному решению владельца FIN-243 исключается только точный пакет `<module>/internal/pgtest`.
Вложенные и похожие по имени пакеты остаются включены; других исключений файлов или пакетов нет.
Пустой список инструментирования приводит к ошибке. Все тесты по-прежнему запускаются через `./...`, включая harness.
Округление инструмента принимает 79,95% как 80,0%. Generated production-код и остальные helpers в обычных `.go` вне исключённого пакета входят в расчёт.
Combined — дополнительный union через штатный comma-profile инструмента; он не заменяет отдельные пороги.

`make cover-unit`, `make cover-integration`, `make cover-api` собирают свежие профили и JSON-логи с `-race` и
ограничением времени, затем проверяют порог. `make cover` выполняет все три проверки. Инвентаризация с `-race`
отклоняет тесты без префикса уровня. Unit не используют сеть/БД; integration работают с настоящими зависимостями;
API проверяют публичный Go API со стороны потребителя, а stateful-сценарии — с реальной БД в транзакции потребителя.
Исполняемые `Example…` входят в API; примеры без Output остаются проверкой компиляции.

Пустой suite, skip/fail фактического теста и отсутствующий/пустой/header-only профиль — ошибка. Недоступный PostgreSQL
в CI также приводит к ошибке. Обязательный job `go` требует успеха всех шести collection/check шагов. Профили
`unit.out`, `integration.out`, `api.out`, JSON-логи и штатные отчёты сохраняются в artifacts, результаты — в сводке CI.
Совместимость Go API отдельно проверяет прежний job `api` (`gorelease`). Собственного расчёта процентов и комментария
в PR больше нет. Порог дополняет ревью полноты сценариев; недостигнутые критерии указываются явно.

Проверка `api` устойчива к публикации тега во время CI: release-коммит сравнивается
с предыдущим выпуском, удалённый тег проверяется по commit до и после `gorelease`.
Подробности и границы исключения — [docs/releasing.md](docs/releasing.md#проверка-версии-в-ci-fin-264).

## Общий Go CI и линтеры (FIN-372)

`.finassist-ci.json` закрепляет отдельный общий источник `fin-assist/go-ci` полным SHA и объявляет профиль/исключения. CI вызывает reusable workflows того же SHA; `make lint`, `make fmt`, `make lint-config` и `make lint-migrations BASE_REF=origin/main` используют его через `scripts/common_ci.py`. Конфигурации создаются в игнорируемом `.finassist-ci/generated/`; локальные копии правил не редактируются. Первый локальный вызов требует доступ к GitHub. Обновление workflow и manifest pin приходит одним PR Renovate; откат возвращает прежние SHA вместе. [Источник, профили, обновление и откат](https://github.com/fin-assist/go-ci/blob/main/docs/shared-go-ci.md). Проверки тестов/coverage, PostgreSQL 18, race и совместимость сохраняются.

Если новая ревизия общего источника меняет `common/bootstrap.py`, в том же PR обновить `scripts/common_ci.py` точными байтами из закреплённого SHA вместе со всеми pins. Byte-equality contract намеренно отклонит частичный переход; конфиги линтеров обратно не копируются. Откат возвращает прежние pins и соответствующую копию bootstrap вместе. Человеческий коммит для такой синхронизации переводит Renovate PR в ручное сопровождение: автомерж FIN-211 к нему больше не применяется.
