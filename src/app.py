from flask import Flask, render_template, request, redirect, url_for
from Crypto.Hash import SHA256
from user import User
from blockchain import Blockchain
import os

from PIL import Image
import imagehash

app = Flask(__name__)
users = []
blockchain = Blockchain()

UPLOAD_FOLDER = '../upload'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    auth_failed = request.args.get('auth_failed')
    app.logger.info(auth_failed)
    return render_template('index.html', auth_failed=auth_failed)


@app.route('/login', methods=['POST'])
def login():
    username = request.form['usernameInput']
    password = request.form['passwordInput']
    app.logger.info(username)
    app.logger.info(password)

    for user in users:
        if user.username != username:
            continue

        hash = SHA256.new(password.encode())
        password_hash = hash.hexdigest()
        if (password_hash == user.password):
            return redirect(url_for('home', username=username, password=password))
        else:
            return redirect(url_for('index', auth_failed=True))
    
    users.append(User(username, password))
    return redirect(url_for('home', username=username, password=password))


@app.route('/home/<username>')
def home(username=None):
    return render_template('home.html', username=username, password=request.args.get('password'))


@app.route('/upload', methods=['POST'])
def upload():
    image = request.files['uploadImage']
    username = request.args.get('username')
    password = request.args.get('password')
    app.logger.info(password)

    path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
    image.save(path)

    hash = imagehash.crop_resistant_hash(Image.open(path))
    author = None
    for user in users:
        if user.username == username:
            author = user

    blockchain.add_block(author, author.sign(hash, password), hash)
    app.logger.info(blockchain.chain[-1])

    return redirect(url_for('home', username=username, password=password))


@app.route('/verify', methods=['POST'])
def verify():
    image = request.files['verifyImage']

    path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
    image.save(path)

    hash = imagehash.crop_resistant_hash(Image.open(path))
    match = blockchain.search(hash)
    
    return render_template('verify.html', match=match)

if __name__ == "__main__":
    app.run(debug=True)