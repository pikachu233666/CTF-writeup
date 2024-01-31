# Espionage CTF - ISSessions 2024

**Write by Gabriel S**

## Cryptography

### Sensitive Files

When you open the text file, you can see a random string`=0HJfhHMG9FRAJ1eGR1QldWYu9WawNXR`, it start with = and has 32 characters, so we reverse it, and then decrypt it with base64 , we can get the flag `EspionageCTF{R@D_F0x_$}`

### The Encryptor

First we see the random string is end with =, so use base64 decrypt and we get 

`Mediocre cypher skills, you can't break into my maximum security encryption methods, for sure you do not understand this:
59 6F 75 20 65 78 70 65 63 74 65 64 20 79 6F 75 72 20 66 6C 61 67 20 74 6F 20 62 65 20 68 61 6E 64 65 64 20 74 6F 20 79 6F 75 20 6F 6E 20 61 20 73 69 6C 76 65 72 20 70 6C 61 74 65 3F 20 49 20 6B 6E 65 77 20 49 20 63 6F 75 6C 64 20 66 6F 6F 6C 20 79 6F 75 2E 2E 2E 20 79 6F 75 20 77 61 6E 74 20 69 74 3F 20 47 6F 20 67 65 74 20 69 74 3A 20 52 66 63 76 62 61 6E 74 72 50 47 53 7B 51 33 50 45 31 43 47 31 30 41 5F 41 30 30 4F 7D `

We can recognize it as Hex, and we get `You expected your flag to be handed to you on a silver plate? I knew I could fool you... you want it? Go get it: RfcvbantrPGS{Q3PE1CG10A_A00O}`

### Data Dump

After looking at `aabaa baaab abbba abaaa abbab abbaa aaaaa aabba aabaa aaaba baaba aabab aaabb abbab ababa abbba aabbb abaaa abbaa`, use Bacon Cipher Decode to decode it, get `ESPIONAGECTFDOLPHIN`, and we get the flag `EspiongeCTF{DOLPHIN}`

### The Encryptor 2

```
TWVkaW9jcmUgY3lwaGVyIHNraWxscywgeW91IGNhbid0IGJyZWFrIGludG8gbXkgbWF4aW11bSBzZWN1cml0eSBlbmNyeXB0aW9uIG1ldGhvZHMsIGZvciBzdXJlIHlvdSBkbyBub3QgdW5kZXJzdGFuZCB0aGlzOgo1OSA2RiA3NSAyMCA2NSA3OCA3MCA2NSA2MyA3NCA2NSA2NCAyMCA3OSA2RiA3NSA3MiAyMCA2NiA2QyA2MSA2NyAyMCA3NCA2RiAyMCA2MiA2NSAyMCA2OCA2MSA2RSA2NCA2NSA2NCAyMCA3NCA2RiAyMCA3OSA2RiA3NSAyMCA2RiA2RSAyMCA2MSAyMCA3MyA2OSA2QyA3NiA2NSA3MiAyMCA3MCA2QyA2MSA3NCA2NSAzRiAyMCA0OSAyMCA2QiA2RSA2NSA3NyAyMCA0OSAyMCA2MyA2RiA3NSA2QyA2NCAyMCA2NiA2RiA2RiA2QyAyMCA3OSA2RiA3NSAyRSAyRSAyRSAyMCA3OSA2RiA3NSAyMCA3NyA2MSA2RSA3NCAyMCA2OSA3NCAzRiAyMCA0NyA2RiAyMCA2NyA2NSA3NCAyMCA2OSA3NCAzQSAyMCA1MiA2NiA2MyA3NiA2MiA2MSA2RSA3NCA3MiA1MCA0NyA1MyA3QiA1MSAzMyA1MCA0NSAzMSA0MyA0NyAzMSAzMCA0MSA1RiA0MSAzMCAzMCA0RiA3RCA=

```

Because it is end with =, try base64 decode, and get `RfcvbantrPGS{Q3PE1CG10A_A00O}`, because the format is Espionage, using ROT13 to decode it you can get `EspionageCTF{D3CR1PT10N_N00B}`

### XY_Encryption

After see the graph, I recognize it is Vigenère cipher, so we can check it in the graph, and we get flag `EspionageCTF{SHADOW}`

### Farmers Life

After see the document, we can know it is Rail-fence Cipher, which has four columns, so after decrypt it ,we can get the flag`EspionageCTF{SARAHIsAKnownBirdwatcher$}`

## Forensics

### Sketchy

After using the tool to read the QR code, it writes `49sEnm3QqZN18J9YPnjav6UuKuZ8B3rg4gehAa7v`,

The hint is bit coin encode, so it is base58, decrypt and get `EspionageCTF{Sk$tchy_M@LwArE}`

### RDP

use online whiteboard to connect the sticker, then we get flag

## Programming

### Decoy Flag Extraction

`grep -oP "EspionageCTF\{[^}]+\}" haystack.txt`

then we get flag`EspionageCTF{FoundIt!}`

## Web

### Default Dance

In the home page, we can see the login page and the user name of the admin called "SuperDuperCoolAdmin", And we see the URL, and tried to add /login at the end, when I see the name Shawn, I tried to create a account, and it said default password and try it on admin ,and you get the flag `EspionageCTF{bad_passw0rd_policy_smh}`

### Flight Ops

I try to use burp suite to proxy and change the permission in the header to get the flag

## OSINT

### PGP

run the command `pgp public.txt`and we can know the uid is Debra_Spy, the flag is `Espionage{Debra_Spy}`

### Boat Dock

After searching the location on google map, we can see there are many marina near it, measure the distance, we can see only Lax kw'alaams Marina is 44 km away, so the villiage is Lax kw'alaams

### Bitcoin  Case

After searching the address, we can find [RYUK](https://www.trendmicro.com/en_us/what-is/ransomware/ryuk-ransomware.html), we know the type is ransomware and belong to RYUK, so the flag is `EspionageCTF{ransomware_Ryuk}`

### Where are you

According to the TD bank and CandyTopia, you can get the street on the Google Map

### Totally a virus

Because it is a ransom notes, we can search it on the [Virustotal](https://www.virustotal.com/) and we can get see the details and get the flag`EspionageCTF{Y0u_F0und_M3}`

### Taxonomy

First, because we get the hint said it use microsoft's naming method, so we can search it on Google, [Microsoft names threat actors](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming), after we see the picture, we can know it is night tsunami, and we can know it is from the NSO Group, and after search it in wiki, we can know the tool is Pegasus, and the flag is `EspionageCTF{Pegasus}
