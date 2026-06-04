# ---- Этап сборки ----
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app ./...

# ---- Финальный этап ----
# 2a. Минимальный базовый образ: scratch (пустой, без ОС и пакетов)
FROM scratch
# 2c. Копируем только готовый бинарник — ни shell, ни пакетов.
COPY --from=builder /app /app
# 2b. Запуск от непривилегированного пользователя (UID 10001, не root)
USER 10001:10001
# 2d. Открываем только нужный порт
EXPOSE 8080
ENTRYPOINT ["/app"]
