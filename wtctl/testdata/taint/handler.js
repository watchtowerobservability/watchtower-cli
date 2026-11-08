const express = require('express');
const app = express();

function search(db, req, res) {
  const name = req.query.name;
  runQuery(db, name); // user input into the helper
}

function admin(db, req, res) {
  runQuery(db, 'admin'); // constant into the same helper
  db.query('SELECT * FROM t WHERE id = $1', [req.query.id]); // bound parameter
}

function runQuery(db, who) {
  db.query("SELECT * FROM users WHERE name = '" + who + "'");
}

app.get('/ping', (req, res) => {
  const host = parseInt(req.query.host); // numeric conversion breaks the flow
  child_process.exec('ping ' + host);
});
