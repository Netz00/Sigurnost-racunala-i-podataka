# Lab 6 - Linux permissions and ACLs

## 1. Provjera osnovnih informacija o trenutnom računu

- jedinstveni ID koji nam je dodijeljen

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ id
uid=1000(student) gid=1000(student) groups=1000(student),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),114(netdev),1001(docker)
```

- sve grupe kojima pripadamo

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ groups
student adm dialout cdrom floppy sudo audio dip video plugdev netdev docker
```

## 2. Upravljanje korisničkim računima

Dodavanje korisnika

```bash

# 1. način
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo useradd alice3
[sudo] password for student:

# 2. način
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo adduser alice3
Adding user alice3' ... Adding new group alice3' (1004) ...
Adding new user alice3' (1003) with group alice3' ...
Creating home directory /home/alice3' ... Copying files from /etc/skel' ...
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
Changing the user information for alice3
Enter the new value, or press ENTER for the default
Full Name []:
Room Number []:
Work Phone []:
Home Phone []:
Other []:
Is the information correct? [Y/n] y
```

- nove korisnike dodajemo kao superuseri

Brisanje korisničkog računa

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo userdel alice3
```

Prebacivanje na drugog korisnika

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ su - alice
Password:
alice@DESKTOP-7Q0BASR:~$ id
uid=1001(alice) gid=1002(alice) groups=1002(alice)
alice@DESKTOP-7Q0BASR:~$
```

- `su` - **switch user**

## 3. Provjera prava nad direktorijem i datotekom

```bash
alice3@DESKTOP-7Q0BASR:~$ mkdir srp
alice3@DESKTOP-7Q0BASR:~$ cd srp/
alice3@DESKTOP-7Q0BASR:~/srp$ echo Hello World > security.txt
alice3@DESKTOP-7Q0BASR:~/srp$ ls -l
total 4
-rw-rw-r-- 1 alice3 alice3 12 Jan 11 11:24 security.txt
alice3@DESKTOP-7Q0BASR:~/srp$ cat security.txt
Hello World
alice3@DESKTOP-7Q0BASR:~/srp$ getfacl security.txt
# file: security.txt
# owner: alice3
# group: alice3
user::rw-
group::rw-
other::r--

alice3@DESKTOP-7Q0BASR:~/srp$ getfacl .
# file: .
# owner: alice3
# group: alice3
user::rwx
group::rwx
other::r-x
```

- `getfacl` - **Get File Access Control List**
- direktorij - execute pravo - odnosi se na naredbu `cd`

## 4. Izmjena prava nad direktorijem i datotekom

Oduzimanje prava čitanja korisniku(sami sebi)

```bash
alice3@DESKTOP-7Q0BASR:~/srp$ chmod u-r security.txt
alice3@DESKTOP-7Q0BASR:~/srp$ cat security.txt
cat: security.txt: Permission denied
alice3@DESKTOP-7Q0BASR:~/srp$ getfacl security.txt
# file: security.txt
# owner: alice3
# group: alice3
user::-w-
group::rw-
other::r--
```

Davanje prava čitanja korisniku

```bash
alice3@DESKTOP-7Q0BASR:~/srp$ chmod u+r security.txt
alice3@DESKTOP-7Q0BASR:~/srp$ cat security.txt
Hello World
```

Posredno blokiranje prava čitanja datoteka u direktoriju

```bash
alice3@DESKTOP-7Q0BASR:~/srp$ chmod u-x .
alice3@DESKTOP-7Q0BASR:~/srp$ cat security.txt
cat: security.txt: Permission denied
```

Ukidanje prava čitanja *others*

```bash
alice3@DESKTOP-7Q0BASR:~/srp$ chmod o-r security.txt
...
bob3@DESKTOP-7Q0BASR:/home/alice3/srp$ cat security.txt
cat: security.txt: Permission denied
```

- ukinemo pravo čitanja *others*, pa bob ne može pročitati datoteku
- ako želimo da bob i dalje može čitati datoteku možemo ga dodati u grupu alice3

## 5. Izmjena grupa

Stvaranje grupe

```bash
student@DESKTOP-7Q0BASR:/home$ sudo groupadd alice_reading_group
```

Dodavanje usera u grupu

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo usermod -aG alice3 bob3
[sudo] password for student:
```

- samo user sa sudo ovlasti može dodavati usere u grupe
- dodani user se treba relogirat da se primjene te promjene

Bob nije u root, ni u ***shadow*** grupi, a others nemaju nikakva prava nad ***shadow*** datotekom pa bob ne može procitati shaddow file, što je dobro jer su tamo hashevi lozinki.

Uklanjanje usera iz grupe

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo gpasswd -d bob3 alice3
Removing user bob3 from group alice3
```

## 6. Izmjena File access Control Lists

- `setfacl` - **Set File Access Control Lists**
- drugi način davanja pristupa
- user se ne treba relogirati

Dodavanje usera u access control listu

```bash
student@DESKTOP-7Q0BASR:/home$ getfacl alice3/srp/security.txt
# file: alice3/srp/security.txt
# owner: alice3
# group: alice3
user::rwx
group::rw-
other::---

student@DESKTOP-7Q0BASR:/home$ sudo setfacl -m u:bob3:r /home/alice3/srp/security.txt
student@DESKTOP-7Q0BASR:/home$ getfacl alice3/srp/security.txt
# file: alice3/srp/security.txt
# owner: alice3
# group: alice3
user::rwx
user:bob3:r--
group::rw-
mask::rw-
other::---

...

bob3@DESKTOP-7Q0BASR:/home/alice3/srp$ cat security.txt
Hello World
```

Dodavanje grupe u access control listu

```bash
student@DESKTOP-7Q0BASR:/home$ sudo groupadd alice_reading_group
student@DESKTOP-7Q0BASR:/home$ sudo setfacl -m g:alice_reading_group:r alice3/srp/security.txt
student@DESKTOP-7Q0BASR:/home$ getfacl alice3/srp/security.txt
# file: alice3/srp/security.txt
# owner: alice3
# group: alice3
user::rwx
user:bob3:r--
group::rw-
group:alice_reading_group:r--
mask::rw-
other::---
```

- dodamo boba toj grupi i onda može čitati datoteku

## 7. Procesi

- kada pokrenemo proces on preuzima identitet od trenutnog korisnika

```bash
student@DESKTOP-7Q0BASR:/$ sudo nano lab6_g3.py
student@DESKTOP-7Q0BASR:/$ getfacl lab6_g3.py
# file: lab6_g3.py
# owner: root
# group: root
user::rw-
group::r--
other::r--
student@DESKTOP-7Q0BASR:/$ python lab6_g3.py
Real (R), effective (E) and saved (S) UIDs:
(1000, 1000, 1000)
Traceback (most recent call last):
File "lab6_g3.py", line 6, in <module>
with open('/home/alice/srp/security.txt', 'r') as f:
IOError: [Errno 13] Permission denied: '/home/alice/srp/security.txt'
```

- skripta je imala prava *others* koji ne mogu procitati datoteku

```bash
student@DESKTOP-7Q0BASR:/$ sudo python lab6_g3.py
Real (R), effective (E) and saved (S) UIDs:
(0, 0, 0)
Hello world
```

- kada se pokrene sa sudo funkcionira
- također ako se pokrene kao bob funkcionira jer bob ima prava čitanja

## 8. Izmjena lozinki

- bob minja password sa `passwd`, ali on nema pravo pisanja u shaddow
- ovaj program je specijalan(`passwd`), pa bez obzira tko pokrene on privremeno preuzima identitet admin usera

```bash
student@DESKTOP-7Q0BASR:/$ getfacl $(which passwd)
getfacl: Removing leading '/' from absolute path names
# file: usr/bin/passwd
# owner: root
# group: root
# flags: s--
user::rwx
group::r-x
other::r-x
```