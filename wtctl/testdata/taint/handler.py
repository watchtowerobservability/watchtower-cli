def search(cur, request):
    name = request.args.get("name")
    run_query(cur, name)  # user input into the helper


def admin(cur, request):
    run_query(cur, "admin")  # constant into the same helper
    cur.execute("SELECT * FROM t WHERE id = %s", (request.args.get("id"),))  # bound parameter


def run_query(cur, who):
    cur.execute("SELECT * FROM users WHERE name = '" + who + "'")


def ping(request):
    host = int(request.args.get("host"))  # numeric conversion breaks the flow
    os.system("ping " + str(host))
