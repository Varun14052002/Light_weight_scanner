from flask import Flask, render_template, request
from scanner import check_sql_injection, check_xss


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    results = {
        'sql_injection': check_sql_injection(url),
        'xss': check_xss(url),
    }
    return render_template('results.html', url=url, results=results)


if __name__ == '_main_':
    print("fllllll")
    app.run(debug=True,port=5001)