package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	users = map[string][]byte{}
	mu    sync.RWMutex
)

var page = template.Must(template.New("p").Parse(`<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><title>Invoicer</title></head>
<body>
<h1>DevSecOps РГР — демонстрационное приложение</h1>
<p>{{.Msg}}</p>
<h2>Регистрация</h2>
<form method="post" action="/register">
  Логин: <input name="login"> Пароль: <input type="password" name="password">
  <button>Зарегистрировать</button>
</form>
<h2>Вход</h2>
<form method="post" action="/login">
  Логин: <input name="login"> Пароль: <input type="password" name="password">
  <button>Войти</button>
</form>
</body></html>`))

// 5b. Защита от кликджекинга и базовые security-заголовки.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func render(w http.ResponseWriter, msg string) {
	if err := page.Execute(w, struct{ Msg string }{msg}); err != nil {
		log.Printf("ошибка рендеринга шаблона: %м", err)
	}
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		render(w, "Заполните форму регистрации.")
		return
	}
	login := r.FormValue("login")
	pass := r.FormValue("password")
	if login == "" || pass == "" {
		render(w, "Логин и пароль обязательны.")
		return
	}
	// 5a. Хэширование пароля с помощью bcrypt (соль генерируется автоматически).
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	mu.Lock()
	users[login] = hash
	mu.Unlock()
	render(w, "Пользователь "+login+" зарегистрирован (пароль сохранён в виде bcrypt-хэша).")
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		render(w, "Заполните форму входа.")
		return
	}
	mu.RLock()
	hash, ok := users[r.FormValue("login")]
	mu.RUnlock()
	if !ok || bcrypt.CompareHashAndPassword(hash, []byte(r.FormValue("password"))) != nil {
		render(w, "Неверный логин или пароль.")
		return
	}
	render(w, "Успешный вход!")
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { render(w, "Готово к работе.") })
	mux.HandleFunc("/register", register)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
	if _, err :=  w.Write([]byte("ok")); err != nil {
		log.Printf("ошибка записи ответа healthz: %v", err)}
	 })

	handler := securityHeaders(mux)

	// Сервер с таймаутами — защита от Slowloris и подобных атак (gosec G114).
	 srv := &http.Server{
 		 Addr:              ":8080",
 		 Handler:           handler,
 		 ReadTimeout:       10 * time.Second,
 		 ReadHeaderTimeout: 5 * time.Second,
 		 WriteTimeout:      10 * time.Second,
 		 IdleTimeout:       60 * time.Second,
 	}

	// 5c. Поддержка HTTPS: если заданы TLS_CERT и TLS_KEY — поднимаем TLS.
	cert, key := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY")
	if cert != "" && key != "" {
		log.Printf("Запуск HTTPS на %s", srv.Addr)
		log.Fatal(srv.ListenAndServeTLS(cert, key))
	}
	log.Printf("Запуск HTTP на %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
