from flask import Flask, g, request, jsonify
from flask_cors import CORS
import sqlite3 as sql
import os
import json
import jwt
import base64
import datetime

app = Flask(__name__)
CORS(app)
path = os.path.dirname(__file__)
db_path = path + "/badges.db"
permissions_file = path + "/permissions.json"
secrets_file = path + "/secret.txt"
images_path = path + "/images"

# permissions stored in form:
#   <role>: {
#       "badge": <badge_permissions>,
#       "issuer": <issuer_permissions>,
#       "student": <student_permissions>,
#       "issuance": <issuance_permissions>,
#       "users": [
#           <user_id>, 
#           ...
#       ]
#   }
#
# permissions string represented as combo of "crud" characters, each giving permissions accordingly:
#   c -> create access
#   r -> read access
#   u -> update access
#   d -> delete access
def fetch_permissions(user):
    with open(permissions_file, 'r') as f:
        data = json.load(f)

    ID = str(user["data"]["id"])
    temp = {
        "badge": [],
        "issuer": [],
        "student": [],
        "issuance": []
    }
    for k, v in data.items():
        if ID in v["users"]:
            for obj in temp.keys():
                temp[obj].append(v[obj])

    p = {}
    for k, v in temp.items():
        p[k] = "".join(set(sum([list(t) for t in v], [])))

    return p

def fetch_secret():
    with open(secrets_file, 'r') as f:
        s = f.read()
    return s

def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value) for idx, value in enumerate(row))

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sql.connect(db_path)
        db.row_factory = make_dicts
    return db

def query(query, args=(), one=False):
    con = get_db()
    cur = con.cursor()

    cur.execute(query, args)

    res = cur.fetchall()

    con.commit()
    return (res[0] if res else None) if one else res

def parse_params(params, all_required=True):
    res = {}
    if request.is_json:
        data = request.get_json()
        print(data.keys())
        try:
            for p in params:
                res[p] = data.get(p)
                if all_required and res[p] == None:
                    return None
        except:
            return None
    else:
        print(request.form.keys())
        print(request.form.get("token"))
        try:
            for p in params:
                res[p] = request.form.get(p)
                if all_required and res[p] == None:
                    return None
        except:
            return None
    return res

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route("/api", methods=['GET'])
def api_info():
    return jsonify({
        "version": "1.0",
        "available_routes": {
            "badges": {
                "/badge": "gets all badges",
                "/badge/<id>": "gets a specified badge",
                "/badge/update/<id>": "updates a specified badge with optional passed (name, abbr, type, image, desc, req)",
                "/badge/add": "inserts a new badge when passed (name, abbr, type, image, desc, req)",
                "/badge/delete": "deletes a badge with the provided (name)",
            },
            "students": {
                "/student": "gets all students",
                "/student/<id>": "gets a specified student",
                "/student/update/<id>": "updates a specified student with optional passed (name, email, password)",
                "/student/add": "inserts a new badge when passed (id, name, email, password)",
                "/student/delete": "deletes a student with the provided (id)"
            },
            "issuers": {
                "/issuer": "gets all issuers",
                "/issuer/<id>": "gets a specified issuer",
                "/issuer/update/<id>": "updates a specified issuer with optional passed (name, department, email, password)",
                "/issuer/add": "inserts a new issuer when passed (id, name, department, email, password)",
                "/issuer/delete": "deletes an issue with the provided (id)"
            },
            "issuances": {
                "/badge/issue": "creates a new issuance for a student with provided (student{id}, badge{id}, issuer{id}, date)",
                "/badge/issue/update": "updates an issuance with provided (student{id}, badge{id}, issuer{id}) to a provided (date)",
                "/badge/issue/delete": "deletes an issuance with provided (student{id}, badge{id}, issuer{id})"
            }
        }
    })

# login stuff to return user key
@app.route("/api/login/issuer", methods=['POST'])
def login_issuer():
    auth = request.authorization
    if not auth:
        return jsonify({"error": "Authorization not successful"}), 400
    
    # see if issuer exists
    ident = query("SELECT (id) FROM issuer WHERE email=? AND password=?", [auth.username, auth.password], True)
    if ident is None:
        return jsonify({"error": "Username or password incorrect"}), 400

    token = jwt.encode({"user": auth.username, "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=3600)}, fetch_secret())

    return jsonify({"msg": "Successful login", "token": token, "id": ident}), 200

@app.route("/api/login/student", methods=["POST"])
def login_student():
    auth = request.authorization
    if not auth:
        return jsonify({"error": "Authorization not successful"}), 400

    # see if student exists
    ident = query("SELECT (id) FROM student WHERE email=? AND password=?", [auth.username, auth.password], True)
    if ident is None:
        return jsonify({"error": "Username or password incorrect"}), 400

    token = jwt.encode({"user": auth.username, "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=3600)}, fetch_secret())

    return jsonify({"msg": "Successful login", "token": token, "id": ident["id"]}), 200

def token_required(f):
    def decorated(*args, **kwargs):
        try:
            params = parse_params(["token", "token_type"])
        except:
            return jsonify({"error": "Operation requires an identifying token"}), 400

        try:
            user = jwt.decode(params["token"], fetch_secret(), algorithms="HS256")["user"]
            
            if (params["token_type"] == "issuer"):
                g.current_user = {
                    "type": "issuer",
                    "data": query("SELECT * FROM issuer WHERE email=?", [user], True)
                }
            elif (params["token_type"] == "student"):
                g.current_user = {
                    "type": "student",
                    "data": query("SELECT * FROM student WHERE email=?", [user], True)
                }
            else:
                return jsonify({"error": "invalid token_type provided"}), 400
        except Exception as error:
            return jsonify({"error": "Invalid or expired token"}), 400

        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

@app.route("/api/verify", methods=['POST'])
@token_required
def verify():
    return jsonify({"msg": f"valid token for {g.current_user}"}), 200

# badge CRUD operations
@app.route("/api/badge", methods=['GET'])
def get_badges():
    res = query("SELECT * FROM badge")

    for t in res:
        if t["image"] != None and os.path.exists(t["image"]):
            with open(t["image"], "rb") as f:
                t["image"] = base64.b64encode(f.read()).decode('utf-8')

    return jsonify(res)

@app.route("/api/badge/<int:ident>", methods=['GET'])
def get_badge(ident):
    res = query("SELECT * FROM badge WHERE id=?", [ident], one=True)

    if res["image"] != None and os.path.exists(res["image"]):
        with open(res["image"], "rb") as f:
            res["image"] = base64.b64encode(f.read()).decode('utf-8')

    return jsonify(res)

@app.route("/api/badge/issuer", methods=['POST'])
@token_required
def get_badges_from_issuer():
    print(g.current_user["data"]["id"])
    res = query("SELECT * FROM badge WHERE creator=-1 OR creator=?", [g.current_user["data"]["id"]])
    print(res)

    for t in res:
        if t["image"] != None and os.path.exists(t["image"]):
            with open(t["image"], "rb") as f:
                t["image"] = base64.b64encode(f.read()).decode('utf-8')

    return jsonify(res), 200

@app.route("/api/badge/update/<int:ident>", methods=['POST'])
@token_required
def update_badge(ident):
    # requires update permissions on badge
    #if "u" not in fetch_permissions(g.current_user)["badge"]:
    #    return jsonify({"error": "Insufficient permissions to update badge"}), 400

    toUpdate = query("SELECT * FROM badge WHERE id=?", [ident], True)
    if toUpdate["creator"] != -1 and toUpdate["Creator"] != g.current_user["data"]["id"]:
        return jsonify({"error": "Insufficient permissions to update badge"}), 400

    params = parse_params(["name", "abbr", "type", "image", "desc", "short", "req", "creator"], False)
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    for k, v in params.items():
        if v is not None:
            if k == "creator":
                print(params[k])
                continue
            if k == "image":
                if ',' in params["image"]:
                    current = query("SELECT * FROM badge WHERE id=?", [ident], True);
                    os.remove(current["image"])

                    img = base64.b64decode(params["image"].split(',')[1])
                    ext = params["image"].split(';')[0].split('/')[1]

                    with open(f"{images_path}/{current['abbr']}.{ext}", "wb") as f:
                        f.write(img)

                    res = query(f"UPDATE badge SET image=? WHERE id=?", ["{images_path}/current['abbr']}.{ext}", ident])

                continue

            res = query(f"UPDATE badge SET {k}=? WHERE id=?", [v, ident])

    return jsonify({"msg": f"Successfully updated badge {ident} with passed params"}), 200


@app.route("/api/badge/add", methods=['POST'])
@token_required
def insert_badge():
    # requires create permissions on badge
    #if "c" not in fetch_permissions(g.current_user)["badge"]:
    #    return jsonify({"error": "Insufficient permissions to create badge"}), 400

    # requires create permissions on badge
    params = parse_params(["name", "abbr", "type", "image", "desc", "short", "req", "creator"])
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    if ',' in params["image"]:
        img = base64.b64decode(params["image"].split(',')[1])

        # get file extension
        ext = params["image"].split(';')[0].split('/')[1]

        with open(f"{images_path}/{params['abbr']}.{ext}", "wb") as f:
            f.write(img)

    res = query("INSERT INTO badge (name, abbr, type, image, desc, short, req, creator) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [params["name"], params["abbr"], params["type"], f"{images_path}/{params['abbr']}.{ext}", params["desc"], params["short"], params["req"], params["creator"]])
    
    return jsonify({"msg": f"Successfully inserted {params["name"]} into badges table"}), 200

@app.route("/api/badge/delete", methods=['POST'])
@token_required
def delete_badge():
    # requires delete permissions on badge
    #if "d" not in fetch_permissions(g.current_user)["badge"]:
    #    return jsonify({"error": "Insufficient permissions to delete badge"}), 400

    params = parse_params(["id"])
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400
    
    toDelete = query("SELECT * FROM badge WHERE id=?", [params["id"]], True)
    
    if toDelete["creator"] != g.current_user["data"]["id"] and toDelete["creator"] != -1:
        return jsonify({"error": "Insufficient permissions to delete badge"}), 400

    os.remove(toDelete["image"])
    res = query("DELETE FROM badge WHERE id=?", [params["id"]])

    return jsonify({"msg": f"Successfully deleted badge {params["id"]} from badges table"}), 200

# student CRUD operations
@app.route("/api/student", methods=["POST"])
@token_required
def get_students():
    # requires read permissions on student
    #if "r" not in fetch_permissions(g.current_user)["student"]:
    #    return jsonify({"error": "Insufficient permissions to read student"}), 400

    if g.current_user["type"] != "issuer":
        return jsonify({"error": "Insufficient permissions to read student"}), 400

    res = query("SELECT * FROM student")
    return jsonify(res), 200

@app.route("/api/student/<int:ident>", methods=["POST"])
def get_student(ident):
    # requires read permission on student
    #if "r" not in fetch_permissions(g.current_user)["student"]:
    #    return jsonify({"error": "Insufficient permissions to read student"}), 400
    
    if g.current_user["type"] != "issuer":
        return jsonify({"error": "Insufficient permissions to read student"}), 400

    res = query(f"SELECT * FROM student WHERE student.id=?", [ident], True)
    return jsonify(res), 200

@app.route("/api/student/update/<int:ident>", methods=["POST"])
@token_required
def update_student(ident):
    # requires update permissions on student
    if "u" not in fetch_permissions(g.current_user)["student"]:
        return jsonify({"error": "Insufficient permissions to update student"}), 400

    params = parse_params(["name", "email", "password", "salt"], False)
    if params is None or ident is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400
    
    for k, v in params.items():
        if v is not None:
            res = query(f"UPDATE student SET {k}=? WHERE id=?", [v, ident])

    return jsonify({"msg": f"Successfully updated student {ident} with passed params"})

@app.route("/api/student/add", methods=["POST"])
@token_required
def insert_student():
    # requires crteate permissions on student
    if "c" not in fetch_permissions(g.current_user)["student"]:
        return jsonify({"error": "Insufficient permissions to create student"}), 400

    params = parse_params(["name", "email", "password", "salt"])
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    res = query("INSERT INTO student (name, email, password, salt) VALUES (?, ?, ?, ?)", [params["name"], params["email"], params["password"], params["salt"]])

    return jsonify({"msg": f"Successfully inserted {params["name"]} into student table"}), 200

@app.route("/api/student/delete", methods=["POST"])
@token_required
def delete_student():
    # requires delete permissions on student
    if "d" not in fetch_permissions(g.current_user)["student"]:
        return jsonify({"error": "Insufficient permissions to delete student"}), 400
    
    params = parse_params(["id"])
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    res = query("DELETE FROM student WHERE id=?", [params["id"]])

    return jsonify({"msg": f"Successfully deleted {params["id"]} from student table"}), 200

@app.route("/api/student/salt", methods=["POST"])
def get_student_salt():
    params = parse_params(["email"])
    if params is None:
        return jsonify({"error": "failed to fetch all parameters from URL"}), 400

    res = query("SELECT (salt) FROM student WHERE email=?", [params["email"]], True)

    return jsonify(res), 200

# issuer CRUD operations
@app.route("/api/issuer", methods=["POST"])
@token_required
def get_issuers():
    # requires read permissions on issuer
    #if "r" not in fetch_permissions(g.current_user)["issuer"]:
    if g.current_user["type"] != "issuer":
        return jsonify({"error": "Insufficient permissions to read issuer"}), 400

    res = query("SELECT * FROM issuer")
    return jsonify(res), 200

@app.route("/api/issuer/<int:ident>", methods=["POST"])
@token_required
def get_issuer(ident):
    # requires read permissions on issuer
    #if "r" not in fetch_permissions(g.current_user)["issuer"]:
    if g.current_user["type"] != "issuer":
        return jsonify({"error": "Insufficient pertmissions to read issuer"}), 400

    if request.method == "GET":
        res = query(f"SELECT * FROM issuer WHERE id=?", [ident], True)
        return jsonify(res), 200

@app.route("/api/issuer/update/<int:ident>", methods=["POST"])
@token_required
def update_issuer(ident):
    # requires update permissons on issuer
    if "u" not in fetch_permissions(g.current_user)["issuer"]:
        return jsonify({"error": "Insufficient permissions to update issuer"}), 400

    params = parse_params(["name", "department", "email", "password", "salt"], False)
    if params is None or ident is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    for k, v in params.items():
        if v is not None:
            res = query(f"UPDATE issuer SET {k}=? WHERE id=?", [v, ident])

    return jsonify({"msg": f"Successfully updated issuer {ident} with passed params"}), 200

@app.route("/api/issuer/add", methods=["POST"])
@token_required
def insert_issuer():
    # requires create permissions on issuer
    #if "c" not in fetch_permissions(g.current_user)["issuer"]:
    #    return jsonify({"error": "Insufficient permissions to create issuer"}), 400

    params = parse_params(["name", "department", "email", "password", "salt"])
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    res = query("INSERT INTO issuer (name, department, email, password, salt) VALUES (?, ?, ?, ?, ?)", [params["name"], params["department"], params["email"], params["password"], params["salt"]])

    return jsonify({"msg": f"Successfully inserted {params["name"]} into issuer table"}), 200

@app.route("/api/issuer/delete", methods=["POST"])
@token_required
def delete_issuer():
    # requires delete permissions on issuer
    if "d" not in fetch_permissions(g.current_user)["issuer"]:
        return jsonify({"error": "Insufficient permissions to delete issuer"}), 400

    params = parse_params(["id"])
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    res = query("DELETE FROM issuer WHERE id=?", [params["id"]])

    return jsonify({"msg": f"Successfully deleted {params["id"]} from issuer table"}), 200

@app.route("/api/issuer/salt", methods=["POST"])
def get_issuer_salt():
    params = parse_params(["email"])
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    res = query("SELECT (salt) FROM issuer WHERE email=?", [params["email"]], True)

    return jsonify(res), 200

# issuance CRUD operations
@app.route("/api/student/<int:ident>/badges", methods=["POST"])
@token_required
def get_issuances_from_student(ident):
    # requires read permissions on issuance
    #if g.current_user["type"] != "student" and "r" not in fetch_permissions(g.current_user["data"])["issuance"]:
    #    return jsonify({"error": "Insufficient permissions to read issuances"}), 400

    if g.current_user["type"] == "student":
        res = query("SELECT badge.id as 'badge_id', badge.name as 'badge_name', badge.abbr, badge.desc, badge.req, badge.image, badge.type, badge.short, badge.creator, student.id as 'student_id', student.name as 'student_name', issuance.date FROM badge JOIN issuance ON issuance.badge=badge.id JOIN student ON issuance.student=student.id WHERE student.id=?", [ident], one=False)
    else:
        res = query("SELECT badge.id as 'badge_id', badge.name as 'badge_name', badge.abbr, badge.desc, badge.req, badge.image, badge.type, badge.short, badge.creator, student.id as 'student_id', student.name as 'student_name', issuance.date FROM badge JOIN issuance ON issuance.badge=badge.id JOIN student ON issuance.student=student.id WHERE student.id=? AND issuance.issuer=?", [ident, g.current_user["data"]["id"]], one=False)
    print(res)

    if res is None:
        return jsonify({"error": "Failed to fetch any issuances"}), 400

    temp = []
    for obj in res:
        t = obj
        if t["image"] != None and os.path.exists(t["image"]):
            with open(t["image"], "rb") as f:
                t["image"] = base64.b64encode(f.read()).decode('utf-8')
        temp.append(t)

    return jsonify(temp), 200

@app.route("/api/badge/issue", methods=["POST"])
@token_required
def get_issuances():
    #if "r" not in fetch_permissions(g.current_user)["issuance"]:
    if g.current_user["type"] != "issuer":
        return jsonify({"error": "Insufficient permissions to get issuance"}), 400
    
    if "r" in fetch_permissions(g.current_user)["issuance"]:
        res = query("SELECT * FROM issuance")
    else:
        res = query("SELECT * FROM issuance WHERE issuer=?", [g.current_user["data"]["id"]])

    return jsonify(res), 200

@app.route("/api/badge/issue/add", methods=["POST"])
@token_required
def issue_badge():
    # requires create permissions on issuance
    #if "c" not in fetch_permissions(g.current_user)["issuance"]:
    if g.current_user["type"] != "issuer":
        return jsonify({"error": "Insufficient permissions to create issuance"}), 400

    params = parse_params(["badge", "student", "issuer", "date"])
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    res = query("INSERT INTO issuance (badge, student, issuer, date) VALUES (?, ?, ?, ?)", [params["badge"], params["student"], params["issuer"], params["date"]])

    return jsonify({"msg": f"Successfully issued {params["badge"]} to {params["student"]} by {params["issuer"]} on {params["date"]}"}), 200

@app.route("/api/badge/issue/update", methods=["POST"])
@token_required
def update_issuance():
    # requires update permissions on issuance
    #if "u" not in fetch_permissions(g.current_user)["issuance"]:
    #    return jsonify({"error": "Insufficient permissions to update issuance"}), 400

    params = parse_params(["badge", "student", "issuer", "date"])
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    toUpdate = query("SELECT * FROM issuance WHERE badge=? AND student=? AND issuer=?", [params["badge"], params["student"], params["issuer"]], True)
    if toUpdate["issuer"] != g.current_user["data"]["id"] and "u" not in fetch_permissions(g.current_user)["issuance"]:
        return jsonify({"error": "Insufficient permissions to update issuance"}), 400
    
    res = query("UPDATE issuance SET date=? WHERE badge=? AND student=? AND issuer=?", [params["date"], params["badge"], params["student"], params["issuer"]])

    return jsonify({"msg": f"Successfully updated issuance of {params["badge"]} to {params["student"]} by {params["issuer"]} to {params["date"]}"}), 200

@app.route("/api/badge/issue/delete", methods=["POST"])
@token_required
def delete_issuance():
    # requires delete permissions on issuance
    #if "d" not in fetch_permissions(g.current_user)["issuance"]:
    #    return jsonify({"error": "Insufficient permissions to delete issuance"}), 400

    params = parse_params(["badge", "student", "issuer"])
    if params is None:
        return jsonify({"error": "Failed to fetch all parameters from URL"}), 400

    toDelete = query("SELECT * FROM issuance WHERE badge=? AND student=? AND issuer=?", [params["badge"], params["student"], params["issuer"]], True)
    if toDelete["issuer"] != g.current_user["data"]["id"] and "d" not in fetch_permissions(g.current_user)["issuance"]:
        return jsonify({"error": "Insufficient permissions to delete issuance"}), 400
    
    res = query("DELETE FROM issuance WHERE badge=? AND student=? AND issuer=?", [params["badge"], params["student"], params["issuer"]])

    return jsonify({"msg": f"Successfully deleted issuance of {params["badge"]} to {params["student"]} by {params["issuer"]}"}), 200

# permission CRUD operations
@app.route("/api/permission/<int:ident>", methods=["GET"])
def get_permission(ident):
    res = fetch_permissions(ident)

    return jsonify(res), 200

if __name__ == "__main__":
    # to run the CloudFlare tunnel:
    #       cloudflared tunnel --url http://localhost:3000
    # to run the Flask server:
    #       python3 main.py
    app.run(port=8081)
