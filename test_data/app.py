import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = os.popen(f"sqlite3 db.sqlite '{query}'").read()
    return result

@app.route("/run", methods=["POST"])
def run_command():
    # Command Injection vulnerability
    cmd = request.form["cmd"]
    output = subprocess.call(cmd, shell=True)
    return str(output)

@app.route("/read", methods=["GET"])
def read_file():
    # Path Traversal vulnerability
    filename = request.args.get("file")
    with open(filename, "r") as f:
        return f.read()

if __name__ == "__main__":
    app.run(debug=True)
