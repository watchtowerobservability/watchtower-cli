package taint

import (
	"database/sql"
	"net/http"
)

func Search(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	runQuery(db, name) // user input into the helper
}

func Admin(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	runQuery(db, "admin")                                        // constant into the same helper
	db.Query("SELECT * FROM t WHERE id = $1", r.FormValue("id")) // bound parameter
}

func runQuery(db *sql.DB, who string) {
	db.Query("SELECT * FROM users WHERE name = '" + who + "'")
}
