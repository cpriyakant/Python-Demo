from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def hello():
    name = request.args.get('name')
    return f"Hello, {name}!"  # Vulnerable to XSS Test 1

if __name__ == '__main__':
    app.run(debug=True)
