from flask import Flask, request
import os

app = Flask(__name__)

# Vulnerability 1: Hardcoded secret key (Insecure cryptographic key)
SECRET_KEY = "my_very_secret_key"

@app.route('/')
def hello():
    name = request.args.get('name')
    return f"Hello, {name}!"  # Vulnerable to XSS

@app.route('/exec')
def insecure_code():
    # Vulnerability 2: Use of eval() (Potentially dangerous code execution)
    code = request.args.get('code')
    if code:
        result = eval(code)  # Extremely dangerous
        return f"Executed code: {result}"
    return "No code provided."

@app.route('/list')
def insecure_command():
    # Vulnerability 3: OS command injection
    directory = request.args.get('dir')
    if directory:
        command = "ls " + directory  # Vulnerable to command injection
        output = os.popen(command).read()
        return f"Directory listing:\n{output}"
    return "No directory provided."

if __name__ == '__main__':
    app.run(debug=True)
