# Изменения

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии и выпуск — [docs/releasing.md](docs/releasing.md). Каждый PR, который меняет API или поведение библиотеки, добавляет строку в «Unreleased»; при выпуске раздел получает номер версии и дату.

## [Unreleased]

### Добавлено

- FIN-119: проверка JWT пользователя и ServiceAccount, ключи и короткие токены стенда с запретом в prod, кэш JWKS с ротацией и ограничением refresh, таблица вызывающих и контекст, unary/stream интерцепторы, HTTP-middleware, маскирование metadata, метрики отказов и инструкция внедрения; unit-, интеграционные и usage-тесты.
