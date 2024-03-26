package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"algorithm.csie.ncku.edu.tw/config"
	"github.com/kataras/go-sessions/v3"
	"golang.org/x/crypto/acme/autocert"
)

var studentIDList []string

// var session
func main() {
	port := flag.Int("p", 8080, "Port number (default: 8080)")
	flag.Parse()
	cfg := config.LoadConfig()

	// web server
	mux := http.NewServeMux()
	session := sessions.New(sessions.Config{})
	loadStudentList()
	mux.HandleFunc("/api/refresh", func(w http.ResponseWriter, r *http.Request) {
		loadStudentList()
	})
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		s := session.Start(w, r)
		w.Header().Add("Content-Type", "application/json")
		if r.Method == "POST" {
			receiver := struct {
				StudentID string `json:"student_id"`
			}{}
			sender := struct {
				Err string `json:"err"`
				// Token string `json:"token"`
			}{}

			decoder := json.NewDecoder(r.Body)
			encoder := json.NewEncoder(w)
			if err := decoder.Decode(&receiver); err != nil {
				sender.Err = err.Error()
				encoder.Encode(sender)
				return
			}

			pass := false
			for i := range studentIDList {
				if receiver.StudentID == studentIDList[i] {
					pass = true
				}
			}
			if pass {
				s.Set("isLogin", true)
				sender.Err = ""
				encoder.Encode(sender)
				return
			}
			sender.Err = "Authentication Fail"
			encoder.Encode(sender)
			return
		} else if r.Method == "GET" {
			sender := struct {
				IsLogin bool `json:"is"`
			}{}
			encoder := json.NewEncoder(w)
			if pass, err := s.GetBoolean("isLogin"); err == nil && pass {
				sender.IsLogin = true
				encoder.Encode(sender)
				return
			}
			sender.IsLogin = false
			encoder.Encode(sender)
			return
		}
	})
	mux.HandleFunc("/api/file", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Add("Content-Type", "application/json")
			queries := r.URL.Query()
			sender := struct {
				Err   string `json:"err"`
				Files []struct {
					Name string `json:"name"`
					URL  string `json:"url"`
				} `json:"files"`
			}{}
			encoder := json.NewEncoder(w)
			if !queries.Has("dir") {
				sender.Err = "params error"
				encoder.Encode(sender)
				return
			}
			dir := queries.Get("dir")
			// 注意安全漏洞
			if dirEntry, err := os.ReadDir(path.Join("./files/", dir)); err != nil {
				sender.Err = "params error"
				encoder.Encode(sender)
				return
			} else {
				for _, f := range dirEntry {
					if !f.IsDir() {
						sender.Files = append(sender.Files, struct {
							Name string `json:"name"`
							URL  string `json:"url"`
						}{
							f.Name(),
							path.Join("./files/", dir, f.Name()),
						})
					}
				}
				encoder.Encode(sender)
			}
		}
	})

	mux.Handle("/files/", http.StripPrefix("/files/", neuter(http.FileServer(http.Dir("./files/")), true, session)))
	mux.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir("./angular/"))))

	// TLS Manager
	var tlsConfig *tls.Config
	if *port == 443 {
		if cfg.Autocert {
			cer, err := tls.LoadX509KeyPair(cfg.Certification.Crt, cfg.Certification.Key)
			if err != nil {
				panic(err)
			}
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}}
		} else {
			tls := &autocert.Manager{
				Cache:      autocert.DirCache("./"),
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(cfg.Domain, "www."+cfg.Domain),
			}

			tlsConfig = tls.TLSConfig()
		}
	}

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", *port),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// https://stackoverflow.com/questions/32325343/go-tcp-too-many-open-files-debug
	// try to solve "too many open files debug" bug
	http.DefaultClient.Timeout = time.Minute * 60

	if *port == 443 {
		fmt.Println("https://localhost")
		go http.ListenAndServe(":80", http.HandlerFunc(redirect))
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalln("ListenAndServe: ", err)
		}
	} else {
		fmt.Printf("http://localhost:%d\n", *port)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalln("ListenAndServe: ", err)
		}
	}
}

func neuter(next http.Handler, auth bool, session *sessions.Sessions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL.Path)
		if auth {
			s := session.Start(w, r)
			if pass, err := s.GetBoolean("isLogin"); err != nil || !pass {
				fmt.Fprintf(w, "Access deny")
				return
			}
		}
		if strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, "/error/403", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func redirect(w http.ResponseWriter, req *http.Request) {
	target := "https://" + req.Host + req.URL.Path
	if len(req.URL.RawQuery) > 0 {
		target += "?" + req.URL.RawQuery
	}
	http.Redirect(w, req, target, http.StatusTemporaryRedirect)
}

func loadStudentList() {
	studentIDList = []string{}

	f, err := os.Open("login.txt")
	if err != nil {
		// skip error
		return
	}
	defer f.Close()
	var id string

	for _, e := fmt.Fscanln(f, &id); e == nil; _, e = fmt.Fscanln(f, &id) {
		studentIDList = append(studentIDList, id)
	}
}
