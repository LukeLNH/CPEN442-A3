from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from base64 import b64encode
from Crypto.Util.Padding import pad, unpad
from Crypto import Random

PROTOCOL = b"PROTOCOL"
CLIENT = b"CLNT"
SERVER = b"SRVR"
SEPERATOR = b"SEPERATORLHKAJSHFKUHDSKJFFK"

# https://asecuritysite.com/encryption/getprimen
# Generated 128 bit prime numbers
p = 256282428810585846751330807206456834043
g = 209949686590672772574212816899428816199

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.diffie_hellman_const = None # DH a or b
        self.challenge = None  # Ra or Rb


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        self.challenge = Random.get_random_bytes(4)
        print(f"Ra: {self.challenge}")
        return PROTOCOL + SEPERATOR + CLIENT + SEPERATOR + self.challenge


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return message[0:len(PROTOCOL)] == PROTOCOL


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message, shared_secret):
        message_parts = message.split(SEPERATOR)
        
        # Bob receives first message from Alice, sends back bob's challenge + alice's challenge response
        if message_parts[1] == CLIENT:
            print("Inside case 1")
            Ra = message_parts[2]
            print(f"Ra: {Ra}")

            self.diffie_hellman_const = int.from_bytes(Random.get_random_bytes(4), byteorder='big')
            gbmodp = (g^self.diffie_hellman_const) % p

            self.challenge = Random.get_random_bytes(4)

            challenge_response = SERVER + SEPERATOR + Ra + SEPERATOR + gbmodp.to_bytes(length=16, byteorder='big')

            cipher = AES.new(self.hash_shared_secret(shared_secret), AES.MODE_CBC)
            iv = cipher.iv
            ciphertext = cipher.encrypt(pad(challenge_response, 16))
            
            return_message = PROTOCOL + SEPERATOR + self.challenge + SEPERATOR + ciphertext + SEPERATOR + iv
            return return_message

        # Alice receives bob's challenge response and bob's challenge
        elif len(message_parts) == 4:
            print("Inside case 2")
            ciphertext = message_parts[2]

            cipher = AES.new(self.hash_shared_secret(shared_secret), AES.MODE_CBC, iv=message_parts[3])

            plaintext = unpad(cipher.decrypt(ciphertext), 16)
            plaintext_parts = plaintext.split(SEPERATOR)

            # print(plaintext_parts)
            
            if plaintext_parts[0] == SERVER:
                Ra = plaintext_parts[1]
                assert self.challenge == Ra, "Incorrect challenge response"

                gbmodp = plaintext_parts[2]
                Rb = message_parts[1]

                self.diffie_hellman_const = int.from_bytes(Random.get_random_bytes(4), byteorder='big')
                gamodp = (g^self.diffie_hellman_const) % p

                # challenge_response = f"{CLIENT},{Rb},{gamodp}"
                challenge_response = CLIENT + SEPERATOR + Rb + SEPERATOR + gamodp.to_bytes(length=16, byteorder='big')
                
                cipher = AES.new(self.hash_shared_secret(shared_secret), AES.MODE_CBC)
                iv = cipher.iv
                ciphertext = cipher.encrypt(pad(challenge_response, 16))

                # return_message = f"{PROTOCOL}{SEPERATOR}{ciphertext}"
                return_message = PROTOCOL + SEPERATOR + ciphertext + SEPERATOR + iv

                self.SetSessionKey((int.from_bytes(gbmodp, byteorder='big')^self.diffie_hellman_const) % p)

                # print(f"Alice's session key: {self._key}")
                return return_message

        # Bob receives alice's challenge response
        elif len(message_parts) == 3:
            print("Inside case 3")
            ciphertext = message_parts[1]

            cipher = AES.new(self.hash_shared_secret(shared_secret), AES.MODE_CBC, iv=message_parts[2])
            plaintext = unpad(cipher.decrypt(ciphertext), 16)
            plaintext_parts = plaintext.split(SEPERATOR)

            if plaintext_parts[0] == CLIENT:
                Rb = plaintext_parts[1]
                assert self.challenge == Rb, "Incorrect challenge response"

                gamodp = plaintext_parts[2]
                self.SetSessionKey((int.from_bytes(gamodp, byteorder='big')^self.diffie_hellman_const) % p)

                # print(f"Bob's session key: {self._key}")

                return None # mutual authentication and key establishment finished, no need to return anything

        raise Exception("Invalid Authentication")


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key.to_bytes(16, "big")


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        data = plain_text.encode("utf-8")
        cipher = AES.new(self._key, AES.MODE_CBC)
        cipher_text = cipher.encrypt(pad(data, 16))
        hmac = HMAC.new(self._key, digestmod=SHA256) 
        hmac.update(cipher_text)
        return cipher.iv + SEPERATOR + cipher_text + SEPERATOR + hmac.digest()


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        hmac = HMAC.new(self._key, digestmod=SHA256)
        iv, data, mac = cipher_text.split(SEPERATOR)
        try: 
            hmac.update(data)
            hmac.verify(mac)
            print("Message integrity verified")
        except ValueError: 
            return "Integrity check failed"
        try: 
            cipher = AES.new(self._key, AES.MODE_CBC, iv)
            plain_text = unpad(cipher.decrypt(data), 16)
        except (ValueError, KeyError):
            return "Incorrect decryption error"
        return plain_text

    def hash_shared_secret(self, shared_secret):
        hash_fn = SHA256.new()
        hash_fn.update(shared_secret.encode())
        return hash_fn.digest()
