import base64
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


def test_png(header):
    if header.startswith(b'\211PNG\r\n\032\n'):
        return True

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

def brute_force():
    # Reading from a file
    filename="c41a24093112661b76c98f2b31bc625706d1fdd4c1a7835a0aa538b98a0aaa2b.encrypted"
    with open(filename, "rb") as file:
        ciphertext = file.read()
        # Now do something with the ciphertext

    ctr = 0
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)
        if not (ctr + 1) % 1000:
            print(f"[*] Keys tested: {ctr + 1:,}",end="\r")
        # Now initialize the Fernet system with the given key
        # and try to decrypt your challenge.
        # Think, how do you know that the key tested is the correct key
        # (i.e., how do you break out of this infinite loop)?
        try:
            plaintext = Fernet(key).decrypt(ciphertext)
            header = plaintext[:32]

            if test_png(header):
                print(f"[+] KEY FOUND: {key} ATTEMPT {ctr + 1}")

                # Writing to a file
                with open("bingo.png", "wb") as file:
                    file.write(plaintext)
                break
        except Exception:
            pass

        ctr += 1

if __name__ == "__main__":
    brute_force()