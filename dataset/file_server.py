import os
from flask import Flask, request, send_file

app = Flask(__name__)


@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = os.path.join('uploads', filename)
    return send_file(filepath)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
