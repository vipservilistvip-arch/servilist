import os
from flask import Flask, send_from_directory

# Obter o caminho absoluto da pasta do projeto
basedir = os.path.abspath(os.path.dirname(__file__))
dist_folder = os.path.join(basedir, 'dist')

app = Flask(__name__, static_folder=dist_folder)

# Serve React App
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    # Tenta servir o arquivo solicitado na pasta dist
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        # Se não encontrar (rotas do React), serve o index.html
        return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    app.run(use_reloader=True, port=5000, threaded=True)
