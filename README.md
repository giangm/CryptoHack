# CryptoHack

|Challenge Name|Points|Category|Flag|
|:--------------:|:------:|:------:|:---------|
|Finding Flags|2|Introduction|crypto{y0ur_f1rst_fl4g}|
|Great Snakes|3|Introduction|crypto{z3n_0f_pyth0n}|
|Network Attacks|5|Introduction|crypto{sh0pp1ng_f0r_fl4g5}|
|ASCII|5|General (Encoding)|crypto{ASCII_pr1nt4bl3}|
|Hex|5|General (Encoding)|crypto{You_will_be_working_with_hex_strings_a_lot}|
|Base64|10|General (Encoding)|crypto/Base+64+Encoding+is+Web+Safe/|
|Bytes and Big Integers|10|General (Encoding)|crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}|
|Encoding Challenge|40|General (Encoding)|crypto{3nc0d3_d3c0d3_3nc0d3}|
|XOR Starter|10|General (XOR)|crypto{aloha}|
|XOR Properties|15|General (XOR)|crypto{x0r_i5_ass0c1at1v3}|
|Favourite byte|20|General (XOR)|crypto{0x10_15_my_f4v0ur173_by7e}|
|You either know, XOR you don't|30|General (XOR)|crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}|
|Lemur XOR|40|General (XOR)||
|Greatest Common Divisor|15|General (Mathematics)|crypto{1512}|

---

## Finding Flags
*Points: 2*
<br/>
Category: <kbd>Introduction</kbd>

### Challenge Description
> Each challenge is designed to help introduce you to a new piece of cryptography. Solving a challenge will require you to find a "flag".
<br/><br/>
These flags will usually be in the format crypto{y0ur_f1rst_fl4g}. The flag format helps you verify that you found the correct solution.
<br/><br/>
Try submitting this into the form below to solve your first challenge.


### Flag: ```crypto{y0ur_f1rst_fl4g}```

---

## Great Snakes
*Points: 3*
<br/>
Category: <kbd>Introduction</kbd>

### Challenge Description
> Modern cryptography involves code, and code involves coding. CryptoHack provides a good opportunity to sharpen your skills.
<br/><br/>
Of all modern programming languages, Python 3 stands out as ideal for quickly writing cryptographic scripts and attacks. For more information about why we think Python is so great for this, please see the [FAQ](https://cryptohack.org/faq/#python3).
<br/><br/>
Run the attached Python script and it will output your flag.

### Given Code
`great_snakes.py`:
``` python
#!/usr/bin/env python3

import sys
# import this

if sys.version_info.major == 2:
    print("You are running Python 2, which is no longer supported. Please update to Python 3.")

ords = [81, 64, 75, 66, 70, 93, 73, 72, 1, 92, 109, 2, 84, 109, 66, 75, 70, 90, 2, 92, 79]

print("Here is your flag:")
print("".join(chr(o ^ 0x32) for o in ords))
```

### Solution
> Run the given code to retrieve the flag.

``` bash
$ python3 a.py
```
```
Here is your flag:
crypto{z3n_0f_pyth0n}
```

### Flag: ```crypto{z3n_0f_pyth0n}```

---

## Network Attacks
*Points: 5*
<br/>
Category: <kbd>Introduction</kbd>

### Challenge Description
> Several of the challenges are dynamic and require you to talk to our challenge servers over the network. This allows you to perform man-in-the-middle attacks on people trying to communicate, or directly attack a vulnerable service. To keep things consistent, our interactive servers always send and receive JSON objects.
<br/><br/>
Python makes such network communication easy with the `telnetlib` module. Conveniently, it's part of Python's standard library, so let's use it for now.
<br/><br/>
For this challenge, connect to `socket.cryptohack.org` on port `11112`. Send a JSON object with the key `buy` and value `flag`.
<br/><br/>
The example script below contains the beginnings of a solution for you to modify, and you can reuse it for later challenges.
<br/><br/>
Connect at `nc socket.cryptohack.org 11112`

### Given Code
`telnetlib_example.py`:
``` python
#!/usr/bin/env python3

import telnetlib
import json

HOST = "socket.cryptohack.org"
PORT = 11112

tn = telnetlib.Telnet(HOST, PORT)


def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    tn.write(request)


print(readline())
print(readline())
print(readline())
print(readline())


request = {
    "buy": "clothes"
}
json_send(request)

response = json_recv()

print(response)
```

### Solution
Examine the JSON object that is being sent in the code.
``` python
request = {
    "buy": "clothes"
}
```
Change the value of `buy` to `flag`, then run the code.
``` python
request = {
    "buy": "flag"
}
```

``` bash
$ python3 a.py
```
```
b"Welcome to netcat's flag shop!\n"
b'What would you like to buy?\n'
b"I only speak JSON, I hope that's ok.\n"
b'\n'
{'flag': 'crypto{sh0pp1ng_f0r_fl4g5}'}
```

### Flag: ```crypto{sh0pp1ng_f0r_fl4g5}```

---

## ASCII
*Points: 5*
<br/>
Category: <kbd>General (Encoding)</kbd>

### Challenge Description
> ASCII is a 7-bit encoding standard which allows the representation of text using the integers 0-127.
<br/><br/>
Using the below integer array, convert the numbers to their corresponding ASCII characters to obtain a flag.
<br/><br/>
`[99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]`

### Solution
Use python to convert and print each ASCII values to a character.

``` python
a = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]

for i in a:
    print(''.join(map(str, chr(i))), end='')

print()

```
The code outputs:
```
crypto{ASCII_pr1nt4bl3}
```

### Flag: ```crypto{ASCII_pr1nt4bl3}```

---

## Hex
*Points: 5*
<br/>
Category: <kbd>General (Encoding)</kbd>

### Challenge Description
> When we encrypt something the resulting ciphertext commonly has bytes which are not printable ASCII characters. If we want to share our encrypted data, it's common to encode it into something more user-friendly and portable across different systems.
<br/><br/>
Included below is a the flag encoded as a hex string. Decode this back into bytes to get the flag.
<br/><br/>
`63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d`

### Solution
Use python to convert hex to bytes.

``` python
print(bytearray.fromhex("63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"))
```
The code outputs:
```
bytearray(b'crypto{You_will_be_working_with_hex_strings_a_lot}')
```

### Flag: ```crypto{You_will_be_working_with_hex_strings_a_lot}```

---

## Base64
*Points: 10*
<br/>
Category: <kbd>General (Encoding)</kbd>

### Challenge Description
> Another common encoding scheme is Base64, which allows us to represent binary data as an ASCII string using 64 characters. One character of a Base64 string encodes 6 bits, and so 4 characters of Base64 encodes three 8-bit bytes.
<br/><br/>
Base64 is most commonly used online, where binary data such as images can be easy included into html or css files.
<br/><br/>
Take the below hex string, decode it into bytes and then encode it into Base64.
<br/><br/>
`72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf`

### Solution
Use python to first convert hex into bytes then encode the byte string using base64.

``` python
import base64

# Given hex string
hex_string = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"

# Convert hex string to byte string
byte_string = bytes.fromhex(hex_string)

# Encode byte string using base64
base64_string = base64.b64encode(byte_string)

print(base64_string)

```
The code outputs:
```
b'crypto/Base+64+Encoding+is+Web+Safe/'
```

### Flag: ```crypto/Base+64+Encoding+is+Web+Safe/```

---

## Bytes and Big Integers
*Points: 10*
<br/>
Category: <kbd>General (Encoding)</kbd>

### Challenge Description
> Cryptosystems like RSA works on numbers, but messages are made up of characters. How should we convert our messages into numbers so that mathematical operations can be applied?
<br/><br/>
The most common way is to take the ordinal bytes of the message, convert them into hexadecimal, and concatenate. This can be interpreted as a base-16 number, and also represented in base-10.
<br/><br/>
To illustrate:
```
message: HELLO
ascii bytes: [72, 69, 76, 76, 79]
hex bytes: [0x48, 0x45, 0x4c, 0x4c, 0x4f]
base-16: 0x48454c4c4f
base-10: 310400273487
```
Python's PyCryptodome library implements this with the methods `Crypto.Util.number.bytes_to_long` and `Crypto.Util.number.long_to_bytes`.
<br/><br/>
Convert the following integer back into a message:
<br/><br/>
`11515195063862318899931685488813747395775516287289682636499965282714637259206269`

### Solution
Use `Crypto.Util.number.long_to_bytes` in python to convert the integer into bytes.
``` python
from Crypto.Util.number import long_to_bytes

big_integer = 11515195063862318899931685488813747395775516287289682636499965282714637259206269

print(long_to_bytes(big_integer))
```
The code outputs:
```
b'crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}'
```

### Flag: ```crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}```

---

## Encoding Challenge
*Points: 40*
<br/>
Category: <kbd>General (Encoding)</kbd>

### Challenge Description
> Now you've got the hang of the various encodings you'll be encountering, let's have a look at automating it.
<br/><br/>
Can you pass all 100 levels to get the flag?
<br/><br/>
The 13377.py file attached below is the source code for what's running on the server. The pwntools_example.py file provides the start of a solution using the incredibly convenient pwntools library. which you can use if you like. pwntools however is incompatible with Windows, so telnetlib_example.py is also provided.
<br/><br/>
For more information about connecting to interactive challenges, see the [FAQ](https://cryptohack.org/faq/#netcat). Feel free to skip ahead to the cryptography if you aren't in the mood for a coding challenge!
<br/><br/>
Connect at `nc socket.cryptohack.org 13377`

### Given Code
`13377.py`:
``` python
#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import listener # this is cryptohack's server-side module and not part of python
import base64
import codecs
import random

FLAG = "crypto{????????????????????}"
ENCODINGS = [
    "base64",
    "hex",
    "rot13",
    "bigint",
    "utf-8",
]
with open('/usr/share/dict/words') as f:
    WORDS = [line.strip().replace("'", "") for line in f.readlines()]


class Challenge():
    def __init__(self):
        self.challenge_words = ""
        self.stage = 0

    def create_level(self):
        self.stage += 1
        self.challenge_words = "_".join(random.choices(WORDS, k=3))
        encoding = random.choice(ENCODINGS)

        if encoding == "base64":
            encoded = base64.b64encode(self.challenge_words.encode()).decode() # wow so encode
        elif encoding == "hex":
            encoded = self.challenge_words.encode().hex()
        elif encoding == "rot13":
            encoded = codecs.encode(self.challenge_words, 'rot_13')
        elif encoding == "bigint":
            encoded = hex(bytes_to_long(self.challenge_words.encode()))
        elif encoding == "utf-8":
            encoded = [ord(b) for b in self.challenge_words]

        return {"type": encoding, "encoded": encoded}

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        if self.stage == 0:
            return self.create_level()
        elif self.stage == 100:
            self.exit = True
            return {"flag": FLAG}

        if self.challenge_words == your_input["decoded"]:
            return self.create_level()

        return {"error": "Decoding fail"}


listener.start_server(port=13377)
```

`pwntools_example.py`:
``` python
from pwn import * # pip install pwntools
import json

r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)


received = json_recv()

print("Received type: ")
print(received["type"])
print("Received encoded value: ")
print(received["encoded"])

to_send = {
    "decoded": "changeme"
}
json_send(to_send)

json_recv()
```

`telnetlib_example.py`:
``` python
import telnetlib
import json

HOST = "socket.cryptohack.org"
PORT = 13377

tn = telnetlib.Telnet(HOST, PORT)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    tn.write(request)

received = json_recv()

print("Received type: ")
print(received["type"])
print("Received encoded value: ")
print(received["encoded"])

to_send = {
    "decoded": "changeme"
}
json_send(to_send)

json_recv()
```

### Solution
Change the `pwntools_example.py` code to the following and run it:
``` python
from pwn import * # pip install pwntools
import json
import codecs
from Crypto.Util.number import long_to_bytes

r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)


received = json_recv()

print("Received type: ")
print(received["type"])
print("Received encoded value: ")
print(received["encoded"])
```
``` python
for t in range(100):

    if received["type"] == "base64":
        decoded = base64.b64decode(received["encoded"].encode()).decode()
        to_send = {
            "decoded": decoded
        }
        json_send(to_send)
    elif received["type"] == "hex":
        decoded = bytes.fromhex(received["encoded"]).decode('utf-8')
        to_send = {
            "decoded": decoded
        }
        json_send(to_send)

    elif received["type"] == "rot13":
        decoded = codecs.decode(received["encoded"], "rot_13")
        to_send = {
            "decoded": decoded
        }
        json_send(to_send)

    elif received["type"] == "bigint":
        decoded = str(long_to_bytes(int(str(received["encoded"]).lstrip("0x"), 16))).strip("b'")
        to_send = {
            "decoded": decoded
        }
        json_send(to_send)

    elif received["type"] == "utf-8":
        decoded = ""
        for i in received["encoded"]:
            decoded += "".join(map(str, chr(i)))
        to_send = {
            "decoded": decoded
        }
        json_send(to_send)

    received = json_recv()
```

After 100 solves, the program will output the flag
```
b'{"flag": "crypto{3nc0d3_d3c0d3_3nc0d3}"}\n'
```

### Flag: ```crypto{3nc0d3_d3c0d3_3nc0d3}```

---

## XOR Starter
*Points: 10*
<br/>
Category: <kbd>General (XOR)</kbd>

### Challenge Description
> XOR is a bitwise operator which returns 0 if the bits are the same, and 1 otherwise. In textbooks the XOR operator is denoted by `⊕`, but in most challenges and programming languages you will see the caret `^` used instead.

| A | B | Output |
|:-:|:-:|:------:|
| 0 | 0 |    0   |
| 0 | 1 |    1   |
| 1 | 0 |    1   |
| 1 | 1 |    0   |

> For longer binary numbers we XOR bit by bit: `0110 ^ 1010 = 1100`. We can XOR integers by first converting the integer from decimal to binary. We can XOR strings by first converting each character to the integer representing the Unicode character.
<br/><br/>
Given the string `"label"`, XOR each character with the integer `13`. Convert these integers back to a string and submit the flag as `crypto{new_string}`.

### Solution
Convert each letter in to a integer and `XOR` it with `13`, then convert each integer back to a character.
``` python
string = "label"
new_string = ""

for i in string:
    new_string += chr(ord(i) ^ 13)

print("crypto{" + new_string + "}")
```

The program output is:
```
crypto{aloha}
```

### Flag: ```crypto{aloha}```

---

## XOR Properties
*Points: 15*
<br/>
Category: <kbd>General (XOR)</kbd>

### Challenge Description
> In the last challenge, you saw how XOR worked at the level of bits. In this one, we're going to cover the properties of the XOR operation and then use them to undo a chain of operations that have encrypted a flag. Gaining an intuition for how this works will help greatly when you come to attacking real cryptosystems later, especially in the block ciphers category.
<br/><br/>
There are four main properties we should consider when we solve challenges using the XOR operator
<br/><br/>
```
Commutative: A ⊕ B = B ⊕ A
Associative: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C
Identity: A ⊕ 0 = A
Self-Inverse: A ⊕ A = 0
```
Let's break this down. Commutative means that the order of the XOR operations is not important. Associative means that a chain of operations can be carried out without order (we do not need to worry about brackets). The identity is 0, so XOR with 0 "does nothing", and lastly something XOR'd with itself returns zero.
<br/><br/>
Let's try this out in action! Below is a series of outputs where three random keys have been XOR'd together and with the flag. Use the above properties to undo the encryption in the final line to obtain the flag.
```
KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf
```

### Hint
> Before you XOR these objects, be sure to decode from hex to bytes. If you have `pwntools` installed, you have a xor function for byte strings: `from pwn import xor`

### Solution
Convert variables into bytes then rearrange the equation `FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf` for FLAG variable.

``` python
from pwn import xor

KEY1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
KEY1_bytes = bytes.fromhex(KEY1)

KEY2n3 = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
KEY2n3_bytes = bytes.fromhex(KEY2n3)

KEY4_bytes = bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")

FLAG_bytes = xor(KEY1_bytes, KEY2n3_bytes, KEY4_bytes)
print(FLAG_bytes)
```
The output is:
```
b'crypto{x0r_i5_ass0c1at1v3}'
```

### Flag: ```crypto{x0r_i5_ass0c1at1v3}```

---

## Favourite byte
*Points: 20*
<br/>
Category: <kbd>General (XOR)</kbd>

### Challenge Description
> I've hidden my data using XOR with a single byte. Don't forget to decode from hex first.
<br/><br/>
`73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d`

### Solution
First decode the given string from hex, then XOR it with every ascii value. Print the result that contains "crypto" in it.
``` python
from pwn import xor

string = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
string_bytes = bytes.fromhex(string)

for i in range(128):
    if "crypto" in str(xor(string_bytes, i)):
        print(xor(string_bytes, i))
```

The output is:
```
b'crypto{0x10_15_my_f4v0ur173_by7e}'
```

### Flag: ```crypto{0x10_15_my_f4v0ur173_by7e}```

---

## You either know, XOR you don't
*Points: 30*
<br/>
Category: <kbd>General (XOR)</kbd>

### Challenge Description
> I've encrypted the flag with my secret key, you'll never be able to guess it.
<br/><br/>
`0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104`

### Hint
> Remember the flag format and how it might help you in this challenge!

### Solution
Decode string from hex into bytes first, then XOR the bytes with "crypto{", this will give part of the key.
``` python
from pwn import xor

string = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
string_bytes = bytes.fromhex(string)

key_bytes = xor(string_bytes, str.encode("crypto{"))
key = key_bytes.decode("utf-8")

# Returns: myXORke+y_Q\x0bOMe$~seG8bGURN\x04FWg)a|\x1dM!an\x7f
```
XOR the bytes with "myXORkey" to retrieve the flag.

``` python
flag = xor(string_bytes, str.encode("myXORkey"))
print(flag)
```

The program returns:
```
b'crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}'
```

### Flag: ```crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}```

---

## Lemur XOR
*Points: 40*
<br/>
Category: <kbd>General (XOR)</kbd>

### Challenge Description
>
### Solution

### Flag: ``` ```

---

## Greatest Common Divisor
*Points: 15*
<br/>
Category: <kbd>General (Mathematics)</kbd>

### Challenge Description
> The Greatest Common Divisor (GCD), sometimes known as the highest common factor, is the largest number which divides two positive integers (a,b).
<br/><br/>
For `a = 12, b = 8` we can calculate the divisors of `a: {1,2,3,4,6,12}` and the divisors of `b: {1,2,4,8}`. Comparing these two, we see that `gcd(a,b) = 4`.
<br/><br/>
Now imagine we take `a = 11, b = 17`. Both `a` and `b` are prime numbers. As a prime number has only itself and `1` as divisors, `gcd(a,b) = 1`.
<br/><br/>
We say that for any two integers `a,b`, if `gcd(a,b) = 1` then `a` and `b` are coprime integers.
<br/><br/>
If a and b are prime, they are also coprime. If `a` is prime and `b < a` then `a` and `b` are coprime.
<br/><br/>
Think about the case for `a` prime and `b > a`, why are these not necessarily coprime?
<br/><br/>
There are many tools to calculate the GCD of two integers, but for this task we recommend looking up [Euclid's Algorithm](https://en.wikipedia.org/wiki/Euclidean_algorithm).
<br/><br/>
Try coding it up; it's only a couple of lines. Use `a = 12, b = 8` to test it.
<br/><br/>
Now calculate `gcd(a,b)` for `a = 66528, b = 52920` and enter it below.
### Solution

``` python
def gcd(a, b):
    if a == 0:
        return b
    else:
        return gcd(b % a, a)

if __name__ == "__main__":
    print(gcd(66528, 52920))
```

Program outputs:
```
1512
```

### Flag: ```crypto{1512}```

---
