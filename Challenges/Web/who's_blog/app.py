import os
from flask import Flask, render_template, render_template_string, request

app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        return render_template("index.html", id = "Sxrhhh")
    elif request.method == "GET":
        id = request.args.get("id")
        if id == None:
            return render_template("index.html", id = "Sxrhhh")
        else:
            with open('templates/index.html', 'r') as f:
                content = f.read()
            evil = content.replace('{{id | safe}}', id)
            return render_template_string(evil)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=80, host="0.0.0.0")


# print(os.urandom(24))