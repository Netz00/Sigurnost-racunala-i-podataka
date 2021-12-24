# Lab 2 - Symmetric key cryptography - a crypto challenge

### Cilj

Dekriptirati personalizirani ciphertext u kontekstu simetrične kriptografije. Izazov počiva na činjenici da student nema pristup enkripcijskom ključu.

### Korištene tehnologije

- Python (version 3)
    - base64
    - hashes
    - [Cryptography](https://cryptography.io/en/latest/)
        - [Fernet](https://cryptography.io/en/latest/fernet/)

### Podizanje radne okoline

Prvo smo unutar direktorija s vjezbama kreirali novi direktorij te ga otvorili

```bash
 C:\Users\A507\bdurdo\mkdir SRP-2021-Lab-2 ; cd SRP-2021-Lab-2
```

Zatim provjeravamo jeli Python instaliran na sustavu i ako je, njegovu verziju

```bash
 python --version
```

Ukoliko je Python instaliran kreiramo virtualno okruzenje za python, da ne bi poremetili rad drugih pyton programa, te ogranicili utjecaj (externalne biblioteke ne instaliravamo globalno).

```bash
python -m venv bdurdo
```

Aktiviranje novog virtualnog okruzenja, sve novoinstalirane biblioteke ce biti vezani za ovo virtualno okruzenje.

```bash
bdurdo/Scripts/activate
```

Sada mozemo primjetiti prefix koji se pojavio ispred putanje direktorija u terminalu,

> (bdurdo) C:\Users\A507\bdurdo\SRP-2021-Lab-2
> 

Zatim instaliramo bibiloteku [cryptography](https://cryptography.io/en/latest/) u Python virtualno okruzenje

```bash
pip install cryptography
```

### Python interpeter

Python interpeter je program pomocu kojeg izvrsavamo druge python programe. Na vjezbama smo koristili dva nacina izvrsavanja python koda, pokretanjem datoteke ili unosenjem direktno u python shell.

Ukoliko nije specificiran program koji zelimo izvrsiti pokrece se python shell gdje mozemo specificirati datoteku koju zelimo pokrenuti ili direktno unositi kod u terminal te izvrsavati ga.

```bash
python <filename>
```

Sljedeci kod pokrecemo direktno putem python shell-a.

Sa sljedecim kodom cemo enkriptirati plaintekst u ciphertekst, te ga dekriptirati ga s tocnim i pogresnim kljucem.

```python
#ukljucivanje fernet biblioteke
>>>fromcryptography.fernetimport Fernet

#generiranje slucajnih brojeva na slucajan nacin, te pohrana u varijablu
>>>key = Fernet.generate_key()

#inicijaliziranje fernet objekt sa tim kljucem
>>>f = Fernet(key)

#prefix b pretvara u format binary
#podaci se moraju poslati funkciji u tom obliku, [specificirano u apiu](https://cryptography.io/en/latest/fernet/#cryptography.fernet.Fernet)
>>>plaintext=b'hello world'

#enkriptiranje poruke  i spremanje u varijablu ciphertext
>>>ciphertext = f.encrypt(plaintext)
>>>ciphertext
b'gAAAAABhdsAxoASl93BugYRU3H3oaR8P2koywHt1kEXcQFNSNrB8JhVvBDsa5aV5JyKFDapBNYCQHbXVzkT1iXDZV1o4WqGGuQ=='

#ispis objekta Fernet klase
>>>f
<cryptography.fernet.Fernet object at 0x000001F05DDBF820>

#dekriptiranje ciphertexta
>>>f.decrypt(ciphertext)
b'hello world'

#pokusaj dekriptiranja s drugim kljucem
key = Fernet.generate_key()
>>> f = Fernet(key)
>>> f.decrypt(ciphertext)
...
cryptography.exceptions.InvalidSignature: Signature did not match digest.
#dobiven error

#izlaz iz pyton shell-a
quit()
```

Sljedeci kod pokrecemo kao datoteku.

Pokretanje VScode u trenutnom direktoriju i otvaranje nove datoteke

```python
code brute_force_g2.py 
```

U novootvorenu datoteku unosimo sljedeci kod te je spremamo.

Zadatak ovog algoritama je da pomocu hash biblioteke (koristeci 256-bit hash) generira ime datoteke koje odgovara hashiranoj verziji naseg imena i prezime `ime_prezime`.

```python
from cryptography.hazmat.primitives import hashes

def hash(input):
	if not isinstance(input, bytes):
		input = input.encode()

	digest = hashes.Hash(hashes.SHA256())
	digest.update(input)
	hash = digest.finalize()
	return hash.hex()

if __name__ == "__main__":
	h = hash('durdov_bozo')
	print(h)
```

Pokretanje i ispis

```python
(bdurdo) C:\Users\A507\bdurdo\SRP-2021-Lab-2>python brute_force_g2.py
c41a24093112661b76c98f2b31bc625706d1fdd4c1a7835a0aa538b98a0aaa2b
```

Pomocu dobivenog hash-a trazimo kriptiranu datoteke te je preuzimamo sa servera.

`a507-server.local`

Na serveru se nalaze direktoriji s nazivima 20 i 22 sto predstavlja broj bitova entropije  kod ključeva koristenih za enkripciju, ili 20 i 22 bit keyspace entropije.

To jest 2^(22) = 4.194.304, 4M kljuceva iz kojih je uzet nas generirani kljuc i s tim kljucem je enkriptiram plaintext koji je potrebno dekriptirati. Po statistici bi trebali naci kljuc u polovici domene kljuceva, 2^(21).

### Bruteforce napad

Kljuc kojim je datoteka enkriptirana generiran je na sljedeci nacin. Tako da su zadnja 22 bita generirana nasumicno, a sve ostalo su 0, tj. niz nula i 22 bita nasumicno odabrana bita.

Rezultat generiranja kljuca su bytovi, a *Fernet* trazi *base64* format stoga je kljuc potrebno prilagoditi.

```python
 # Encryption keys are 256 bits long and have the following format:
 #
 #              0...000b[1]b[2]...b[22]
 #
 # where b[i] is a randomly generated bit.
 key = int.from_bytes(os.urandom(32), "big") & int('1'*KEY_ENTROPY, 2)

 # Initialize Fernet with the given encryption key;
 # Fernet expects base64 urlsafe encoded key.
 key_base64 = base64.urlsafe_b64encode(key.to_bytes(32, "big"))
 fernet = Fernet(key_base64)
```

Pregled danih informacija:

- enkodiran challenge, sacuvan u file i nazvan ga hashem naseg imena - *Ciphertekst*
- tip datoteke *Plainteksta* → jpg i keyspace *Plainteksta*
- algoritam enkriptiranja i dekriptiranja → *Fernet*

Pomocu tih informacija trebamo pronaci kljuc te dekriptiranjem dobiti originalni *Plaintekst*. Da bismo to izveli koristimo bruteforce napad.

![Untitled-2021-10-25-2141(1).png](Lab2-SymmetricKeyCryptography_a_CryptoChallenge/Untitled-2021-10-25-2141(1).png)

Za pocetak iteriramo beskonacnom petljom kroz sve kombinacije kljuceva te ih ispisujemo.

```python
import base64
from cryptography.hazmat.primitives import hashes

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

def brute_force():
    ctr = 0
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)
        print(key_bytes)
        # Now initialize the Fernet system with the given key
        # and try to decrypt your challenge.
        # Think, how do you know that the key tested is the correct key
        # (i.e., how do you break out of this infinite loop)?

        ctr += 1

if __name__ == "__main__":
    brute_force()
```

Zatim ubrzavamo kod tako da umjesto ispisujemo svaki kljuc, ispisujemo broj kljuca i to svako 1000 kljuceva.

```python
import base64
from cryptography.hazmat.primitives import hashes

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

def brute_force():
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

        ctr += 1

if __name__ == "__main__":
    brute_force()
```

Nakon sto smo se uvjerili da sve funkcionira krecemo na drugi dio bruteforce napada, testiranje generiranih kljuceva. Da bismo to izveli prvo moramo ucitati datoteku na kojoj cemo provjeravati kljuceve, tj. ciphertekst. Kljuceve testiramo tako da *Ciphertekst* pokusamo dekriptirati sa njim i ukoliko se dogodi exception test bi trebao podbaciti, ali to se nije pokazalo kao dovoljan uvjet. Stoga koristimo znanje o samom plaintekstu da bi provjerili jeli datoteka uspjesno dekriptirana. Posto znamo da se radi o fotografiji jpg formata ispitujemo samo header dekriptiranog cipherteksta, te ukoliko odgovara headeru fotografije tog formata prekidamo daljnje trazenje kljuca, ispisujemo broj kljuca, kljuc i spremamo fotografiju.

```python
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
```

Nakon nekoliko minuta mozemo vidjeti sljedeci izlaz

> [+] KEY FOUND: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAII28=' ATTEMPT 533360
> 

Trazena fotografija, *Plaintekst*, rezultat dekriptiranja

![Untitled](Lab2-SymmetricKeyCryptography_a_CryptoChallenge/Untitled.png)

*Ciphertekst* nad kojim je vrsen napad

[c41a24093112661b76c98f2b31bc625706d1fdd4c1a7835a0aa538b98a0aaa2b.encrypted](Lab2-SymmetricKeyCryptography_a_CryptoChallenge/c41a24093112661b76c98f2b31bc625706d1fdd4c1a7835a0aa538b98a0aaa2b.encrypted)

Python skripta

[brute_force_g2.py](Lab2-SymmetricKeyCryptography_a_CryptoChallenge/brute_force_g2.py)