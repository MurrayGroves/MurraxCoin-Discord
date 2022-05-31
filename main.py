import discord

from discord.ext import commands

import asyncio
import threading

import websockets
import random
import json
from aioconsole import ainput
import os
import traceback

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Hash import BLAKE2b
from Crypto.Signature import DSS

from nacl.signing import SigningKey

import base64
import zlib

websocketPool = {}

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

import datetime
import time

from collections import Counter


storageDir = "storage/"


os.makedirs(f"{storageDir}keys", exist_ok=True)

global bot
bot = commands.Bot(command_prefix="$")

try:
    f = open(f"{storageDir}handshake_key.pem", "rb")
    handshakeKey = RSA.import_key(f.read())
    f.close()

except FileNotFoundError:
    handshakeKey = RSA.generate(2048)
    toWrite = handshakeKey.export_key()
    f = open(f"{storageDir}handshake_key.pem", "wb+")
    f.write(toWrite)
    f.close()
    del toWrite

handshakePublicKey = handshakeKey.publickey()
handshakePublicKeyStr = handshakePublicKey.export_key()
handshakeCipher = PKCS1_OAEP.new(handshakeKey)

global mentioned_transactions
mentioned_transactions = []

global current_games
current_games = {}


class websocketSecure:
    def __init__(self, url):
        self.url = url

    async def initiateConnection(self):
        try:
            self.websocket = await websockets.connect(self.url)
        except OSError:
            raise TimeoutError
        await self.websocket.send(handshakePublicKeyStr)
        handshakeData = await self.websocket.recv()
        print("Data: " + handshakeData)
        handshakeData = json.loads(handshakeData)

        sessionKey = base64.b64decode(handshakeData["sessionKey"].encode('ascii'))
        #sessionKey = bytes.fromhex(handshakeData["sessionKey"])
        self.sessionKey = handshakeCipher.decrypt(sessionKey)

    @classmethod
    async def connect(cls, url):
        self = websocketSecure(url)
        await asyncio.wait({self.initiateConnection()})
        for i in range(200):
            try:
                self.sessionKey
                return self

            except:
                await asyncio.sleep(0.1)

        raise TimeoutError


    async def recv(self):
        data = await self.websocket.recv()
        ciphertext, tag, nonce = data.split("|||")
        ciphertext, tag, nonce = base64.b64decode(ciphertext).decode("ascii"), base64.b64decode(tag).decode("ascii"), base64.b64decode(nonce).decode("ascii")
        cipher = AES.new(self.sessionKey, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        plaintext = plaintext.decode("ascii")

        return plaintext

    async def send(self, plaintext):
        cipher = AES.new(self.sessionKey, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("ascii"))
        await self.websocket.send(base64.b64encode(ciphertext).decode("ascii") + "|||" + base64.b64encode(tag).decode("ascii") + "|||" + base64.b64encode(cipher.nonce).decode("ascii"))

    async def close(self):
        await self.websocket.close()


async def createWallet(user_id):
    if os.path.exists(f"{storageDir}keys/{user_id}"):
        raise FileExistsError

    seed = os.urandom(32)
    privateKey = SigningKey(seed)
    f = open(f"{storageDir}keys/{user_id}", "wb+")
    f.write(seed)
    f.close()

    publicKey = privateKey.verify_key
    addressChecksum = zlib.adler32(publicKey.encode()).to_bytes(4, byteorder="big")
    addressChecksum = base64.b32encode(addressChecksum).decode("utf-8").replace("=", "").lower()
    address = base64.b32encode(publicKey.encode()).decode("utf-8").replace("=", "").lower()
    publicKeyStr = f"mxc_{address}{addressChecksum}"

    with open(f"{storageDir}users.json") as f:
        old = json.load(f)

    old[user_id] = publicKeyStr

    with open(f"{storageDir}users.json", "w+") as f:
        json.dump(old, f)

    req = {"type": "watchForSends", "address": publicKeyStr}
    await wsRequest(json.dumps(req))

    return publicKeyStr


async def genSignature(data, privateKey):
    data = json.dumps(data).encode()
    signature = privateKey.sign(data).signature
    signature = hex(int.from_bytes(signature, "little"))

    return signature


doBackgroundCheck = True
websocket = None


async def receive(sendAmount, block, publicKeyStr, privateKey):
    global websocket

    resp = await wsRequest(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
    resp = json.loads(resp)

    if resp["type"] != "rejection":
        balance = float(resp["balance"])
        blockType = "receive"
        response = await wsRequest(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
        previous = json.loads(response)["link"]

    else:
        balance = 0
        blockType = "open"
        previous = "0" * 20

    response = await wsRequest(json.dumps({"type": "getRepresentative", "address": publicKeyStr}))
    representative = json.loads(response)["representative"]

    block = {"type": f"{blockType}", "previous": f"{previous}", "address": f"{publicKeyStr}",
             "link": f"{block}", "balance": balance + float(sendAmount), "representative": representative}

    hasher = BLAKE2b.new(digest_bits=512)
    blockID = hasher.update(json.dumps(block).encode("utf-8")).hexdigest()
    block["id"] = blockID
    signature = await genSignature(block, privateKey)
    block = {**block, **{"signature": signature}}
    resp = await wsRequest(json.dumps(block))
    resp = json.loads(resp)

    if resp["type"] == "confirm":
        receiveAmount = sendAmount
        newBalance = block["balance"]
        print(f"\nReceived MXC: {receiveAmount}")
        print(f"New Balance: {newBalance}")

    else:
        print("\nFailed to receive MXC!")
        print(resp)


async def reverse_lookup(address_lookup):
    with open(f"{storageDir}users.json") as f:
        users = json.load(f)

    for i, (user, address) in enumerate(users.items()):
        if address == address_lookup:
            return user

    raise FileNotFoundError


async def sendAlert(data):
    data = json.loads(data)

    with open(f"{storageDir}privKey", "rb") as f:
        privateKey = SigningKey(f.read())

    publicKey = privateKey.verify_key
    addressChecksum = zlib.adler32(publicKey.encode()).to_bytes(4, byteorder="big")
    addressChecksum = base64.b32encode(addressChecksum).decode("utf-8").replace("=", "").lower()
    address = base64.b32encode(publicKey.encode()).decode("utf-8").replace("=", "").lower()
    publicKeyStr = f"mxc_{address}{addressChecksum}"

    if data["address"] == publicKeyStr:
        await receive(data["sendAmount"], data["link"], data["address"], privateKey)

    user = await reverse_lookup(data["address"])

    with open(f"{storageDir}keys/{user}", "rb") as f:
        privateKey = SigningKey(f.read())

    await receive(data["sendAmount"], data["link"], data["address"], privateKey)
    try:
        user = int(user)

    except ValueError:  # Is not a discord user account
        return

    try:
        sender = await reverse_lookup(data["link"].split("/")[0])
        sender = f"<@{sender}>"

    except FileNotFoundError:
        sender = data["link"].split("/")[0]

    global mentioned_transactions
    print(data["link"])
    print(mentioned_transactions)
    if data["link"] not in mentioned_transactions:
        global bot
        user_obj = await bot.fetch_user(user)
        await user_obj.send(f"You have been sent {data['sendAmount']} MXC by {sender}")


async def websocketPoolLoop():
    global websocketPool
    while True:
        await asyncio.sleep(0.03)
        try:
            resp = await asyncio.wait_for(websocket.recv(), 0.5)
            if prevRequest == "":
                if json.loads(resp)["type"] == "sendAlert":
                    asyncio.create_task(sendAlert(resp))

                else:
                    print("Unknown Alert")
                    print(resp)

                continue

            else:
                if json.loads(resp)["type"] == "sendAlert":
                    asyncio.create_task(sendAlert(resp))
                    continue

                websocketPool[prevRequest][1] = resp
                prevRequest = ""

        except ValueError:
            traceback.print_exc()

        except:
            pass

        if len(websocketPool.keys()) > 0:
            poolKeys = list(websocketPool.keys())
            if websocketPool[poolKeys[0]][1] == "":
                await websocket.send(websocketPool[poolKeys[0]][0])
                prevRequest = poolKeys[0]
                websocketPool[poolKeys[0]][1] = 0


async def wsRequest(request):
    global websocketPool
    requestID = random.randint(0, 99999999999999)
    websocketPool[requestID] = [request, ""]
    while True:
        await asyncio.sleep(0.1)
        if websocketPool[requestID][1] != "" and websocketPool[requestID][1] != 0:
            resp = websocketPool[requestID][1]
            websocketPool.pop(requestID)
            return resp


async def startup():
    global websocket
    uri = "ws://murraxcoin.murraygrov.es:6969"
    websocket = await websocketSecure.connect(uri)

    asyncio.create_task(websocketPoolLoop())


    with open(f"{storageDir}users.json") as f:
        users = json.load(f)

    for address in users.values():
        req = {"type": "pendingSend", "address": address}
        resp = await wsRequest(json.dumps(req))
        resp = json.loads(resp)

        if resp["link"] != "":
            resp["address"] = address
            await sendAlert(json.dumps(resp))

        req = {"type": "watchForSends", "address": address}
        await wsRequest(json.dumps(req))

    with open(f"{storageDir}privKey", "rb") as f:
        privateKey = SigningKey(f.read())

    publicKey = privateKey.verify_key
    addressChecksum = zlib.adler32(publicKey.encode()).to_bytes(4, byteorder="big")
    addressChecksum = base64.b32encode(addressChecksum).decode("utf-8").replace("=", "").lower()
    address = base64.b32encode(publicKey.encode()).decode("utf-8").replace("=", "").lower()
    publicKeyStr = f"mxc_{address}{addressChecksum}"

    req = {"type": "watchForSends", "address": publicKeyStr}
    await wsRequest(json.dumps(req))


class GameState:
    def __init__(self, target, challenger, wager, target_address, challenger_address):
        self.target_score = 0
        self.challenger_score = 0
        self.target_choice = None
        self.challenger_choice = None
        self.round = 1
        self.score_threshold = 3  # How many non-draw rounds to be played.

        self.target = target
        self.challenger = challenger
        self.wager = wager
        self.target_address = target_address
        self.challenger_address = challenger_address

    async def update_round(self, interaction, target_choice=None, challenger_choice=None):
        if target_choice is not None:
            self.target_choice = target_choice

        if challenger_choice is not None:
            self.challenger_choice = challenger_choice

        if (self.challenger_choice is not None) and (self.target_choice is not None):  # Both contestants have chosen
            if self.challenger_choice == self.target_choice:
                return 0,

            # 0 => rock, 1 => paper, 2 => scissors
            if self.challenger_choice > self.target_choice and not (self.challenger_choice == 2 and self.target_choice == 0):
                self.challenger_score += 1
                to_return = self.challenger

            else:
                self.target_score += 1
                to_return = self.target

            self.challenger_choice = None
            self.target_choice = None
            self.round += 1

            if self.challenger_score >= self.score_threshold/2 or self.target_score >= self.score_threshold/2:
                winner = self.challenger if self.challenger_score > self.target_score else self.target
                message_object = await interaction.message.reply(f"Match winner: <@{winner}>!")

                with open(f"{storageDir}keys/holding", "rb") as f:
                    privateKey = SigningKey(f.read())

                publicKey = privateKey.verify_key
                addressChecksum = zlib.adler32(publicKey.encode()).to_bytes(4, byteorder="big")
                addressChecksum = base64.b32encode(addressChecksum).decode("utf-8").replace("=", "").lower()
                address = base64.b32encode(publicKey.encode()).decode("utf-8").replace("=", "").lower()
                publicKeyStr = f"mxc_{address}{addressChecksum}"

                resp = await wsRequest(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
                resp = json.loads(resp)
                balance = float(resp["balance"])

                newBalance = balance - (self.wager * 2)
                winner = self.challenger_address if self.challenger_score > self.target_score else self.target_address

                response = await wsRequest(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
                previous = json.loads(response)["link"]

                response = await wsRequest(
                    json.dumps({"type": "getRepresentative", "address": publicKeyStr}))
                representative = json.loads(response)["representative"]

                data = {"type": "send", "address": f"{publicKeyStr}", "link": f"{winner}",
                        "balance": f"{newBalance}",
                        "previous": previous, "representative": representative}

                hasher = BLAKE2b.new(digest_bits=512)
                blockID = hasher.update(json.dumps(data).encode("utf-8")).hexdigest()
                data["id"] = blockID

                global mentioned_transactions
                mentioned_transactions.append(f"{data['address']}/{data['id']}")

                signature = await genSignature(data, privateKey)
                data = {**data, **{"signature": f"{signature}"}}
                resp = await wsRequest(json.dumps(data))
                return 2, message_object

            return 1, to_return


class RPSButton(discord.ui.Button):
    def __init__(self, target, challenger, round_num, game_id, emoji, choice_value):
        self.target = target
        self.challenger = challenger
        self.round_num = round_num
        self.game_id = game_id
        self.choice_value = choice_value
        super().__init__(
            emoji=emoji,
            style=discord.enums.ButtonStyle.primary,
        )

    async def callback(self, interaction: discord.Interaction):
        global current_games
        if interaction.user.id in (self.target, self.challenger) and self.round_num == current_games[self.game_id].round:
            if interaction.user.id == self.target:
                new_state = await current_games[self.game_id].update_round(interaction, target_choice=self.choice_value)

            if interaction.user.id == self.challenger:
                new_state = await current_games[self.game_id].update_round(interaction, challenger_choice=self.choice_value)

        else:
            return

        if new_state:
            if new_state[0] == 0:
                await interaction.message.reply(f"That round was a tie!")

            elif new_state[0] == 1:
                await interaction.message.reply(f"Round winner: <@{new_state[1]}>")

            else:
                old = new_state[1].content
                await new_state[1].edit(content=f"{old}\nYour earnings have been transferred.")
                return

            em = discord.Embed(title=f"Round {current_games[self.game_id].round}",
                               description="Contestants, make your play!",
                               colour=random.randint(0, 16777215))

            view = discord.ui.View(timeout=None)
            view.add_item(RPSButton(self.target, self.challenger, current_games[self.game_id].round, self.game_id, "🪨", 0))
            view.add_item(RPSButton(self.target, self.challenger, current_games[self.game_id].round, self.game_id, "🧻", 1))
            view.add_item(RPSButton(self.target, self.challenger, current_games[self.game_id].round, self.game_id, "✂️", 2))
            await interaction.message.reply(embed=em, view=view)


class ChallengeAcceptButton(discord.ui.Button):
    def __init__(self, target, challenger, wager):
        self.target = target
        self.challenger = challenger
        self.accepted = False
        self.game_id = random.randint(0, 9999999999999999)
        self.wager = wager

        with open(f"{storageDir}users.json") as f:
            users = json.load(f)

        self.target_address = users[str(self.target)]
        self.challenger_address = users[str(self.challenger)]
        super().__init__(
            label="Accept",
            style=discord.enums.ButtonStyle.green,
        )

    async def callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.target or self.accepted:
            return

        # Will not respond to interaction in time due to waiting for the send transaction
        message_object = await interaction.message.reply("Transferring wager to holding...")
        await interaction.response.defer()

        if not os.path.isfile(f"{storageDir}keys/holding"):  # Create a holding wallet if one doesn't exist
            await createWallet("holding")

        resp = await wsRequest(f'{{"type": "balance", "address": "{self.target_address}"}}')
        resp = json.loads(resp)
        target_balance = float(resp["balance"])

        resp = await wsRequest(f'{{"type": "balance", "address": "{self.challenger_address}"}}')
        resp = json.loads(resp)
        challenger_balance = float(resp["balance"])

        self.accepted = True
        if target_balance < self.wager or challenger_balance < self.wager:
            await message_object.edit(content="One of the contestants does not have enough MXC!")
            return

        with open(f"{storageDir}keys/holding", "rb") as f:
            privateKey = SigningKey(f.read())

        publicKey = privateKey.verify_key
        addressChecksum = zlib.adler32(publicKey.encode()).to_bytes(4, byteorder="big")
        addressChecksum = base64.b32encode(addressChecksum).decode("utf-8").replace("=", "").lower()
        address = base64.b32encode(publicKey.encode()).decode("utf-8").replace("=", "").lower()
        publicKeyStr = f"mxc_{address}{addressChecksum}"

        newBalance = challenger_balance - self.wager

        response = await wsRequest(f'{{"type": "getPrevious", "address": "{self.challenger_address}"}}')
        previous = json.loads(response)["link"]

        response = await wsRequest(json.dumps({"type": "getRepresentative", "address": self.challenger_address}))
        representative = json.loads(response)["representative"]

        data = {"type": "send", "address": f"{self.challenger_address}", "link": f"{publicKeyStr}", "balance": f"{newBalance}",
                "previous": previous, "representative": representative}

        with open(f"{storageDir}keys/{self.challenger}", "rb") as f:
            privateKey = SigningKey(f.read())

        hasher = BLAKE2b.new(digest_bits=512)
        blockID = hasher.update(json.dumps(data).encode("utf-8")).hexdigest()
        data["id"] = blockID
        signature = await genSignature(data, privateKey)
        data = {**data, **{"signature": f"{signature}"}}
        resp = await wsRequest(json.dumps(data))

        newBalance = target_balance - self.wager

        response = await wsRequest(f'{{"type": "getPrevious", "address": "{self.target_address}"}}')
        previous = json.loads(response)["link"]

        response = await wsRequest(json.dumps({"type": "getRepresentative", "address": self.target_address}))
        representative = json.loads(response)["representative"]

        data = {"type": "send", "address": f"{self.target_address}", "link": f"{publicKeyStr}", "balance": f"{newBalance}",
                "previous": previous, "representative": representative}

        with open(f"{storageDir}keys/{self.target}", "rb") as f:
            privateKey = SigningKey(f.read())

        hasher = BLAKE2b.new(digest_bits=512)
        blockID = hasher.update(json.dumps(data).encode("utf-8")).hexdigest()
        data["id"] = blockID
        signature = await genSignature(data, privateKey)
        data = {**data, **{"signature": f"{signature}"}}
        resp = await wsRequest(json.dumps(data))

        global current_games
        current_games[self.game_id] = GameState(self.target, self.challenger, self.wager, self.target_address, self.challenger_address)

        em = discord.Embed(title="Round 1",
                           description="Contestants, make your play!",
                           colour=random.randint(0, 16777215))

        view = discord.ui.View(timeout=None)
        view.add_item(RPSButton(self.target, self.challenger, 1, self.game_id, "🪨", 0))
        view.add_item(RPSButton(self.target, self.challenger, 1, self.game_id, "🧻", 1))
        view.add_item(RPSButton(self.target, self.challenger, 1, self.game_id, "✂️", 2))
        await message_object.edit(content="", embed=em, view=view)


@bot.slash_command()
async def rps(ctx, amount: float, user: discord.User):
    """Challenge someone to rock paper scissors!"""
    if user.id == ctx.author.id:
        await ctx.respond("You cannot play rock paper scissors with yourself!")
        return
        
    view = discord.ui.View(timeout=None)

    view.add_item(ChallengeAcceptButton(target=user.id, challenger=ctx.author.id, wager=amount))

    await ctx.respond(
        f"<@{user.id}>, you have been challenged to rock paper scissors with a wager of {amount} MXC!",
        view=view
    )


@bot.slash_command()
async def send(ctx, amount: float, user: discord.User):
    """Send MXC to someone. If you use it in a reply, you do not need to specify a recipient."""
    mentioned = False

    if not user:
        await ctx.respond("You must specify a recipient if not used in a reply.")

    else:
        with open(f"{storageDir}users.json") as f:
            users = json.load(f)

        try:
            target = users[str(user.id)]

        except:
            target = createWallet(str(user.id))

        mentioned = True

    with open(f"{storageDir}users.json") as f:
        users = json.load(f)

    address = users[str(ctx.author.id)]

    message_obj = await ctx.respond("Attempting transaction...")

    resp = await wsRequest(f'{{"type": "balance", "address": "{address}"}}')
    resp = json.loads(resp)

    if resp["type"] != "rejection":
        balance = float(resp["balance"])

    else:
        balance = 0

    amount = float(amount)
    newBalance = balance - amount

    response = await wsRequest(f'{{"type": "getPrevious", "address": "{address}"}}')
    previous = json.loads(response)["link"]

    response = await wsRequest(json.dumps({"type": "getRepresentative", "address": address}))
    representative = json.loads(response)["representative"]

    data = {"type": "send", "address": f"{address}", "link": f"{target}", "balance": f"{newBalance}",
            "previous": previous, "representative": representative}

    with open(f"{storageDir}keys/{ctx.author.id}", "rb") as f:
        privateKey = SigningKey(f.read())

    hasher = BLAKE2b.new(digest_bits=512)
    blockID = hasher.update(json.dumps(data).encode("utf-8")).hexdigest()
    data["id"] = blockID
    signature = await genSignature(data, privateKey)
    data = {**data, **{"signature": f"{signature}"}}
    if mentioned:
        print("Mentioned")
        global mentioned_transactions
        mentioned_transactions.append(f"{data['address']}/{data['id']}")
    resp = await wsRequest(json.dumps(data))
    if json.loads(resp)["type"] == "confirm":
        print("MXC send initiated!")
        await message_obj.edit_original_message(content=f"Sent {amount} MXC to <@{user.id}>.\nTransaction has ID `{data['id']}`")

    else:
        print("MXC send failed to initiate, please see error below:")
        print(resp)
        await message_obj.edit_original_message(content=f"MXC send failed to initiate. Error: `{resp}`")


@bot.slash_command()
async def address(ctx, user: discord.User = None):
    """Check someone's MXC address, defaults to you if no user is specified."""
    if user:
        user = str(user.id)

    else:
        user = str(ctx.author.id)

    with open(f"{storageDir}users.json") as f:
        users = json.load(f)

    try:
        address = users[user]

    except:
        address = await createWallet(str(ctx.author.id))

    await ctx.respond(f"<@{user}>'s address is: `{address}`")


@bot.slash_command()
async def balance(ctx, user: discord.User = None):
    """Check someone's balance, defaults to you if no user is specified."""
    if user:
        user = str(user.id)

    else:
        user = str(ctx.author.id)

    with open(f"{storageDir}users.json") as f:
        users = json.load(f)

    address = users[user]

    resp = await wsRequest(f'{{"type": "balance", "address": "{address}"}}')
    resp = json.loads(resp)

    if resp["type"] != "rejection":
        balance = float(resp["balance"])

    else:
        balance = 0

    await ctx.respond(f"<@{user}>'s balance: `{balance}` MXC")


@bot.slash_command()
async def ping(ctx):
    """Check if the bot is online"""
    await ctx.respond("pong")


@bot.slash_command()
async def leaderboard(ctx):
    resp = await wsRequest(f'{{"type": "getAccounts"}}')
    resp = json.loads(resp)
    accounts = resp["accounts"]
    for account in accounts:
        accounts[account] = float(accounts[account])

    top = dict(Counter(resp["accounts"]).most_common(10))

    count = 1
    em = discord.Embed(title="Leaderboard", colour=random.randint(0, 16777215))
    for account in top:
        try:
            address = await reverse_lookup(account)
            user = await bot.fetch_user(address)
            address = user.name + "#" + user.discriminator

        except:
            address = f"{account}"
            pass

        to_add = f"{top[account]} MXC ({round((top[account]/1000000)*100,2)}%)"
        em.add_field(name=f"{count}. {address}", value=to_add, inline=False)
        count += 1

    await ctx.respond(embed=em)


@bot.slash_command()
async def claim(ctx):
    """Claim your daily MXC"""

    with open(f"{storageDir}timeouts.json") as f:
        old = json.load(f)

    try:
        if (old[str(ctx.author.id)] + 86400) > time.time():
            delay = (old[str(ctx.author.id)] + 86400) - time.time()
            await ctx.respond(f"Please wait {int(delay//3600)} hours, {int((delay/60)%60)} minutes")
            return

    except KeyError:
        pass

    with open(f"{storageDir}privKey", "rb") as f:
        privateKey = SigningKey(f.read())

    publicKey = privateKey.verify_key
    addressChecksum = zlib.adler32(publicKey.encode()).to_bytes(4, byteorder="big")
    addressChecksum = base64.b32encode(addressChecksum).decode("utf-8").replace("=", "").lower()
    address = base64.b32encode(publicKey.encode()).decode("utf-8").replace("=", "").lower()
    publicKeyStr = f"mxc_{address}{addressChecksum}"

    message_obj = await ctx.respond("Attempting transaction...")

    with open(f"{storageDir}users.json") as f:
        users = json.load(f)

    try:
        address = users[str(ctx.author.id)]

    except:
        address = await createWallet(str(ctx.author.id))

    resp = await wsRequest(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
    resp = json.loads(resp)

    if resp["type"] != "rejection":
        balance = float(resp["balance"])

    else:
        balance = 0

    amount = balance * 0.0001
    newBalance = balance - amount

    response = await wsRequest(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
    previous = json.loads(response)["link"]

    response = await wsRequest(json.dumps({"type": "getRepresentative", "address": publicKeyStr}))
    representative = json.loads(response)["representative"]

    data = {"type": "send", "address": f"{publicKeyStr}", "link": f"{address}", "balance": f"{newBalance}",
            "previous": previous, "representative": representative}

    hasher = BLAKE2b.new(digest_bits=512)
    blockID = hasher.update(json.dumps(data).encode("utf-8")).hexdigest()
    data["id"] = blockID
    signature = await genSignature(data, privateKey)
    data = {**data, **{"signature": f"{signature}"}}
    global mentioned_transactions
    mentioned_transactions.append(f"{data['address']}/{data['id']}")
    resp = await wsRequest(json.dumps(data))

    if json.loads(resp)["type"] == "confirm":
        print("MXC send initiated!")
        await message_obj.edit_original_message(content=f"You have claimed {amount} MXC!\n Transaction ID: `{data['id']}`")

    else:
        print("MXC send failed to initiate, please see error below:")
        print(resp)
        await message_obj.edit_original_message(content=f"MXC send failed to initiate. Error: `{resp}`")

    old[str(ctx.author.id)] = time.time()

    with open(f"{storageDir}timeouts.json", "w+") as f:
        json.dump(old, f)


@bot.event
async def on_ready():
    print("Connected")
    game = discord.Game("/help")
    await bot.change_presence(status=discord.Status.online, activity=game)
    asyncio.create_task(startup())


with open(f"{storageDir}token.dat") as f:
    token = f.read().strip()

bot.run(token)
