import config, aiohttp, datetime
from sanic import Sanic, response
from sanic_motor import BaseModel
from pymongo import ReturnDocument
from sanic_jinja2 import SanicJinja2
from cryptography.fernet import Fernet

async def checkAES():
    try:
        keyfile = open(r'keys\key.aes', 'rb')
        key = keyfile.read()
        keyfile.close()
    except FileNotFoundError:
        keyfile = open(r'keys\key.aes', 'wb')
        key = Fernet.generate_key()
        keyfile.write(key)
        keyfile.close()
    return key

async def generate_tokens(code):

    data = {
        'client_id': config.CLIENT_ID,
        'client_secret': config.CLIENT_SECRET,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': config.CALLBACK_URL
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    async with aiohttp.ClientSession(headers=headers) as cs:
        async with cs.post('https://osu.ppy.sh/oauth/token', data=data) as r:
            res = await r.json()
            return int(res['expires_in']), res['access_token'], res['refresh_token']

app = Sanic(__name__)

settings = {
    "MOTOR_URI": config.DB_URI,
    "LOGO": None
}

app.config.update(settings)

BaseModel.init_app(app)
jinja = SanicJinja2(app, autoescape=True)
fernetModel = None

class Authorization(BaseModel):
    __coll__ = 'oauth'
    __unique_fields__ = ['secret, expires_on, access_token, refresh_token']

@app.listener('before_server_start')
async def setup_encryption(app, loop):
    key = await checkAES()
    global fernetModel
    fernetModel = Fernet(key)

@app.route('/')
async def main(request):
    global fernetModel

    arguments = ['code', 'state']
    if not all(item in request.args.keys() for item in arguments):
        return response.text(f"At least one of the required arguments are missing. {arguments}", status=400)

    try:

        state_string = ''.join(request.args['state'])
        code = ''.join(request.args['code'])
        secret = fernetModel.decrypt(state_string.encode())
        stringified_secret = secret.decode()

        expires_in, access_token, refresh_token = await generate_tokens(code)
        expires_on = datetime.datetime.now() + datetime.timedelta(seconds=expires_in)

        auth = await Authorization.find_one_and_update(
            {'secret': stringified_secret},
            {
                '$set': {
                    'expires_on': expires_on,
                    'access_token': access_token,
                    'refresh_token': refresh_token
                }
            },
            return_document = ReturnDocument.AFTER
        )
        if not auth:
            raise Exception('Authorization does not exist in database.')

        SUCCESS = True

    except Exception:
        SUCCESS = False

    if SUCCESS:
        return response.json({'args': request.args, 'success': SUCCESS})
    return response.json({'success': SUCCESS})

@app.route('/create_auth_request')
async def create_auth_request(request):
    global fernetModel

    arguments = ['discordID', 'passkey']
    if not all(item in request.args.keys() for item in arguments):
        return response.text(f"At least one of the required arguments are missing. {arguments}", status=400)

    discordID = ''.join(request.args['discordID'])
    passkey = ''.join(request.args['passkey'])

    if passkey == config.APP_PASSKEY:
        secret = fernetModel.encrypt(discordID.encode())
        stringified_secret = str(secret.decode())

        obj = {
            'secret': discordID
        }

        await Authorization.update_one(obj, {
            "$set": obj
        }, upsert=True)

        return response.json({'encrypted_secret': stringified_secret, 'url': f"https://osu.ppy.sh/oauth/authorize?client_id={config.CLIENT_ID}&redirect_uri={config.CALLBACK_URL}&response_type=code&scope=identify&state={stringified_secret}"})
    return response.text("You do not have permission to access this endpoint.", status=403)

if __name__ == '__main__':
    app.run(host='localhost', port=8000)