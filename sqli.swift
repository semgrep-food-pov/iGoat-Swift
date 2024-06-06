let username = someField.text()
let password = a.text()

let sql = "SELECT * FROM semgrep_users WHERE username = '\(username)' AND password = '\(password)'"

// ruleid:swift-sqlite-injection
let result = sqlite3_exec(db, sql, nil, nil, nil)
sqlite3_close(db)

let sql = "SELECT * FROM semgrep_users WHERE username = 'admin' AND password = '\(password)'"
// ruleid:swift-sqlite-injection
let result = sqlite3_exec(db, sql, nil, nil, nil)
sqlite3_close(db)


let sql = "SELECT * FROM semgrep_users WHERE username = ? AND password = ?"
var stmt: OpaquePointer?
// ok:swift-sqlite-injection
if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
    sqlite3_bind_text(stmt, 1, username, -1, nil)
    sqlite3_bind_text(stmt, 2, password, -1, nil)
    if sqlite3_step(stmt) == SQLITE_DONE {
        // SUCCESS
    }
}

sqlite3_finalize(stmt)
sqlite3_close(db)

let sql = "SELECT * FROM semgrep_users WHERE username = 'admin' AND password = 'admin'"
// ok:swift-sqlite-injection
let result = sqlite3_exec(db, sql, nil, nil, nil)
sqlite3_close(db)


let sql = "SELECT * FROM semgrep_users WHERE username = 'admin' AND password = '" + password + "'"
// ruleid:swift-sqlite-injection
let result = sqlite3_exec(db, sql, nil, nil, nil)
sqlite3_close(db)


let sql = "SELECT * FROM semgrep_users WHERE username = ? AND password = '" + password + "'"
// ruleid:swift-sqlite-injection
if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
    sqlite3_bind_text(stmt, 1, username, -1, nil)
    if sqlite3_step(stmt) == SQLITE_DONE {
        // SUCCESS
    }
}

sqlite3_finalize(stmt)
sqlite3_close(db)
