package main

import (
	"bufio"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/sessions"

	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"io/ioutil"
)

var store = sessions.NewCookieStore([]byte("secret-key"))
var try = 3
var secret_key = "key"

type User struct {
	Login              string
	Password           string
	IsBlocked          bool
	PasswordRestricted bool
}

// Генерация MD5 хэша на основе ключа
func generateMD5Key(secret string) []byte {
	hash := md5.Sum([]byte(secret))
	return hash[:]
}

// PKCS7Padding добавляет PKCS7-заполнение для выравнивания данных
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// EncryptCTR осуществляет потоковое шифрование в режиме CTR
func EncryptCTR(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Создаем вектор инициализации (IV)
	iv := make([]byte, block.BlockSize())
	stream := cipher.NewCTR(block, iv)

	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

func hashing() {
	// Генерация ключа MD5
	key := generateMD5Key("your-secret-key")

	// Чтение содержимого файла
	plaintext, _ := ioutil.ReadFile("db.txt")

	// Шифрование данных в режиме CTR
	ciphertext, err := EncryptCTR(key, plaintext)
	if err != nil {
		fmt.Println("Ошибка при шифровании:", err)
		return
	}

	// Запись зашифрованного файла
	err = ioutil.WriteFile("db_encrypted.txt", ciphertext, 0644)
	if err != nil {
		fmt.Println("Ошибка при записи зашифрованного файла:", err)
		os.Exit(1)
	}
}

// DecryptCTR осуществляет потоковое расшифрование в режиме CTR
func DecryptCTR(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Создаем вектор инициализации (IV)
	iv := make([]byte, block.BlockSize())
	stream := cipher.NewCTR(block, iv)

	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func PKCS7UnPadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

func unhashing() {
	key := generateMD5Key("your-secret-key")

	ciphertext, _ := ioutil.ReadFile("db_encrypted.txt")

	// Расшифрование данных в режиме CTR
	plaintext, err := DecryptCTR(key, ciphertext)
	if err != nil {
		fmt.Println("Ошибка при расшифровании:", err)
		return
	}

	fmt.Println(string(plaintext))
	if string(plaintext) != "admin,,false,false\n" {
		fmt.Println("Данные некоректно расшифрованы", err)
		os.Exit(1)
	}

	err = ioutil.WriteFile("db.txt", plaintext, 0644)
	if err != nil {
		fmt.Println("Ошибка при записи расшифрованного файла:", err)
		os.Exit(1)
	}
}

func check_secret_key(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("templates/check_secret_key.html")
	if r.Method == http.MethodPost {
		key := r.FormValue("key")
		if key != secret_key {
			go func() {
				timer := time.After(5 * time.Second)
				<-timer
				os.Exit(0)
				return
			}()
			tmpl.Execute(w, "Пароль неверный! Завершение работы программы через 5 секунд!")
			return
		} else {
			unhashing()
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	}
	tmpl.Execute(w, nil)
}

func f(w http.ResponseWriter, r *http.Request) {
	login := r.FormValue("login")
	action := r.FormValue("action")
	users := read_users()
	for i, val := range users {
		if val.Login == login {
			if action == "0" {
				users[i].IsBlocked = !users[i].IsBlocked
			} else {
				users[i].PasswordRestricted = !users[i].PasswordRestricted
			}
			break
		}
	}
	update_users(users)
	http.Redirect(w, r, "/all_user", http.StatusSeeOther)
}

func update_users(users []User) {
	file, _ := os.OpenFile("db.txt", os.O_RDWR|os.O_TRUNC, 0666)
	defer file.Close()
	file.Truncate(0)
	for _, val := range users {
		userData := fmt.Sprintf("%s,%s,%t,%t\n", val.Login, val.Password, val.IsBlocked, val.PasswordRestricted)
		file.WriteString(userData)
	}
}

func read_users() []User {
	file, _ := os.Open("db.txt")
	defer file.Close()
	var users []User
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ",")
		if len(fields) != 4 {
			continue
		}
		isBlocked := fields[2] == "true"
		passwordRestricted := fields[3] == "true"
		user := User{
			Login:              fields[0],
			Password:           fields[1],
			IsBlocked:          isBlocked,
			PasswordRestricted: passwordRestricted,
		}
		users = append(users, user)
	}
	return users
}

func new_user(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("templates/new_user.html")
	session, err := store.Get(r, "user-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if session.Values["user"] != "admin" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		file, _ := os.OpenFile("db.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		defer file.Close()
		name := r.FormValue("username")
		users := read_users()
		fl := true
		for _, val := range users {
			if val.Login == name {
				fl = false
				break
			}
		}
		if fl {
			userData := fmt.Sprintf("%s,%s,%t,%t\n", name, "", false, false)
			file.WriteString(userData)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else {
			tmpl.Execute(w, "Пользователь уже существует")
			return
		}
	}
	tmpl.Execute(w, nil)
}

func all_user(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("templates/all_user.html")
	session, err := store.Get(r, "user-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if session.Values["user"] != "admin" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	users := read_users()
	us := struct {
		Users []User
	}{users}
	tmpl.Execute(w, us)
}

func profile(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("templates/profile.html")
	session, err := store.Get(r, "user-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, session.Values["user"])
}

func exit(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "user-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if session.Values["user"] != nil {
		session.Options.MaxAge = -1
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		hashing()
		os.Remove("db.txt")
		os.Exit(0)
	}
}

func changing_pass(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("templates/changing_pass.html")
	session, err := store.Get(r, "user-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if session.Values["user"] == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		old_pass := r.FormValue("old_password")
		pass := r.FormValue("password")
		conf_pass := r.FormValue("conf_pass")

		users := read_users()
		var currentUser User
		for _, val := range users {
			if val.Login == session.Values["user"] {
				currentUser = val
				break
			}
		}

		if currentUser.Password != old_pass {
			tmpl.Execute(w, "Старый пароль введен неверно")
			return
		}

		if pass != conf_pass {
			tmpl.Execute(w, "Пароли не совпадают")
			return
		}

		if session.Values["passRestricted"] == true {
			latinLetters := regexp.MustCompile(`[A-Za-z]`)
			cyrillicLetters := regexp.MustCompile(`[А-Яа-я]`)
			digits := regexp.MustCompile(`\d`)

			if !latinLetters.MatchString(pass) || !cyrillicLetters.MatchString(pass) || !digits.MatchString(pass) {
				tmpl.Execute(w, "Пароль должен содержать латинские буквы, кириллические символы и цифры")
				return
			}
		}

		for i, val := range users {
			if val.Login == session.Values["user"] {
				users[i].Password = pass
				break
			}
		}
		update_users(users)
		http.Redirect(w, r, "/exit", http.StatusSeeOther)
	}
	tmpl.Execute(w, nil)
}

func new_password(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("templates/new_password.html")
	session, err := store.Get(r, "user-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if session.Values["user"] == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	if r.Method == http.MethodPost {
		pass := r.FormValue("password")
		conf_pass := r.FormValue("conf_pass")
		if pass != conf_pass {
			tmpl.Execute(w, "Пароли не совпадают")
			return
		}
		if session.Values["passRestricted"] == true {
			latinLetters := regexp.MustCompile(`[A-Za-z]`)
			cyrillicLetters := regexp.MustCompile(`[А-Яа-я]`)
			digits := regexp.MustCompile(`\d`)

			if !latinLetters.MatchString(pass) || !cyrillicLetters.MatchString(pass) || !digits.MatchString(pass) {
				tmpl.Execute(w, "Пароль должен содержать латинские буквы, кириллические символы и цифры")
				return
			}
		}
		users := read_users()
		for i, val := range users {
			if val.Login == session.Values["user"] {
				users[i].Password = pass
			}
		}
		update_users(users)
		http.Redirect(w, r, "/exit", http.StatusSeeOther)
	}
	tmpl.Execute(w, nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("templates/index.html")
	session, err := store.Get(r, "user-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if session.Values["user"] != nil {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	users := read_users()

	if r.Method == http.MethodPost {
		name := r.FormValue("username")
		password := r.FormValue("password")
		for _, val := range users {
			if val.Login == name && val.Password == password {
				session.Values["user"] = val.Login
				session.Values["isBlocked"] = val.IsBlocked
				session.Values["passRestricted"] = val.PasswordRestricted
				break
			}
		}
		if session.Values["user"] == nil {
			try -= 1
			if try == 0 {
				http.Redirect(w, r, "/exit", http.StatusSeeOther)
				return
			}
			tmpl.Execute(w, fmt.Sprintf("Неверный логин или пароль! У вас осталось %d попытки", try))
			return
		}
		try = 3
		if session.Values["isBlocked"] == true {
			session.Options.MaxAge = -1
			tmpl.Execute(w, "Пользователь заблокирован")
			return
		}
		session.Save(r, w)

		// Проверяем, пустой ли пароль
		if password == "" {
			http.Redirect(w, r, "/new_password", http.StatusSeeOther)
			return
		}

		// Проверяем ограничения на пароль, если они есть
		if session.Values["passRestricted"] == true {
			latinLetters := regexp.MustCompile(`[A-Za-z]`)
			cyrillicLetters := regexp.MustCompile(`[А-Яа-я]`)
			digits := regexp.MustCompile(`\d`)

			if !latinLetters.MatchString(password) || !cyrillicLetters.MatchString(password) || !digits.MatchString(password) {
				http.Redirect(w, r, "/changing_pass", http.StatusSeeOther)
				return
			}
		}
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
	}
	tmpl.Execute(w, nil)
}

func about(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("templates/about.html")
	session, err := store.Get(r, "user-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, session.Values["user"])
}

func handle_request() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	http.HandleFunc("/", login)
	http.HandleFunc("/about", about)
	http.HandleFunc("/profile", profile)
	http.HandleFunc("/exit", exit)
	http.HandleFunc("/all_user", all_user)
	http.HandleFunc("/new_user", new_user)
	http.HandleFunc("/changing_pass", changing_pass)
	http.HandleFunc("/new_password", new_password)
	http.HandleFunc("/f", f)
	http.HandleFunc("/check_secret_key", check_secret_key)
	fmt.Println("http://localhost:8080/check_secret_key")
	http.ListenAndServe(":8080", nil)
}

func init_db() {
	_, err := os.Stat("db.txt")
	_, err_2 := os.Stat("db_encrypted.txt")
	if os.IsNotExist(err) && os.IsNotExist(err_2) {
		file, _ := os.Create("db.txt")
		userData := fmt.Sprintf("%s,%s,%t,%t\n", "admin", "", false, false)
		file.WriteString(userData)
		file.Close()
		hashing()
		os.Remove("db.txt")
	}
}

func main() {
	init_db()
	handle_request()
}
