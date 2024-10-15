import os

from flask import Flask, render_template, request, session
from getPIN import get_pin

app = Flask(__name__)
app.secret_key = os.urandom(24)
pin = get_pin()



@app.route('/')
def index():
    return render_template('index.html', pin=pin)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=80)
    # print(get_pin())
