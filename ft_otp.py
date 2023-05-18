import hmac, base64, hashlib, struct, time, re, argparse, qrcode
from cryptography.fernet import Fernet, InvalidToken


def args_init():
    analizador = argparse.ArgumentParser(
        prog="./ft_otp",
        description="Tools to generate a Time-based One-time Password.",
        epilog="Ft_otp's exercise of the Cybersecurity Bootcamp of Fundación 42 (Malaga).",
    )

    analizador.add_argument(
        "-g",
        help="Almacena una contrase encriptada, una llave maestra y un código qr.",
        action='store_true')
    analizador.add_argument(
        "-k",
        metavar="fichero", nargs="*",
        help="Generate a time-based One-time Password using a file 'ft_otp.key' as first argument and 'master_key.key' as second one.",
        type=str)

    return analizador.parse_args()


def input_():
    print()
    password = input("Enter a string to randomize the key creation: ")
    password_hex = password.encode('utf-8').hex()
    if not re.match(r'^[0-9a-fA-F]{64,}$', password_hex):
        print("\n\033[31mThe key encoded in hexadecimal is no longer than 64 characters. You should enter a longer string.\033[39m\n")  
        exit()
    hex2bytes = bytes(password_hex, 'utf-8')
    bytes2b32 = base64.b32encode(hex2bytes)
    secret = bytes2b32.decode('utf-8')
    return secret


def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h


def get_totp_token(secret):
    x =str(get_hotp_token(secret,intervals_no=int(time.time())//30))
    while len(x)!=6:
        x+='0'
    return x


def encrypt_data(secret):
    with open ("master_key.key", "wb") as k:
        master_key = Fernet.generate_key()
        print(master_key)
        f = Fernet(master_key)
        k.write(master_key)
        token = f.encrypt(bytes(secret, 'utf-8'))
    with open ("ft_otp.key", "wb") as f:
        f.write(token)


def decrypt_data(gen_token, gen_token2):
    try:
        with open(gen_token, "rb") as fa:
            file_data = fa.read()
            with open(gen_token2, "rb") as e:
                file_data2 = e.read()
                f = Fernet(file_data2)
            token_decrypt = f.decrypt(file_data)
            return token_decrypt
    except (FileNotFoundError, InvalidToken, IsADirectoryError):
        print("\n\033[31mInvalid file. You should enter a valid file.key.\033[39m\n")
        exit()

def generator_qr(secret):
    qrtest = "otpauth://totp/FT_OTP:BootcampCybersecurity?secret=" + secret+"&issuer=FT_OTP"
    obj = qrcode.make(qrtest)
    imgQr = open("qr.png","wb")
    obj.save(imgQr)
    imgQr.close()


        
# ================================================================================ 

if __name__ == "__main__":

    args = args_init()

    gen_key = args.g
    if not gen_key and not args.k:
        print("\n\033[31mCheck usage model with -h.\033[39m\n")
        
    elif gen_key:
        secret = input_()
        token = encrypt_data(secret)
        generator_qr(secret)
        print("\n\033[32mPassword and master key successfully encrypted.\033[39m\n")
        print("\n\033[32mQR code successfully created.\033[39m\n")
    else:
        if len(args.k) != 2:
            print("\n\033[31mCheck usage model with -h.\033[39m\n")
            exit()
        else:
            gen_token = args.k[0]
            gen_token2 = args.k[1]

            if gen_token and gen_token2:
                    try:
                        token_decrypt = decrypt_data(gen_token, gen_token2)
                        print("\n\033[32mToken successfully created.\033[39m\n")
                        print(get_totp_token(token_decrypt))
                        print("\n\033[32mChecking token in 15 seg....\033[39m\n")
                        time.sleep(15)
                        print(get_totp_token(token_decrypt))
                        print("\n\033[32mChecking another token in 15 seg....\033[39m\n")
                        time.sleep(15)
                        print(get_totp_token(token_decrypt))
                        print()  
                    except ValueError:
                        print("\n\033[31mCheck usage model with -h.\033[39m\n")