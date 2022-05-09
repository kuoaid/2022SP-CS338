from base64 import encode
import hashlib
import binascii
from hmac import digest

def encodeToSHA256(plain):
    encoded_password = plain.encode('utf-8')
    hasher = hashlib.sha256(encoded_password)
    digest = hasher.digest() # type=bytes
    digest_as_hex = binascii.hexlify(digest)
    return digest_as_hex.decode('utf-8')

def batchGuess(data, references):
    results = []
    for point in data:
        username = point[0]
        hashedPW = point[1]
        print("testing "+username)
        for possibility in references:
            PossiblePW = possibility[0]
            hashedPossiblePW = possibility[1]
            # print("testing "+hashedPW+"\nagainst possibility"+hashedPossiblePW)
            if hashedPossiblePW == hashedPW:
                # print("got a hit")
                results.append((username,PossiblePW))
                break
    return results


def main():
    pwData = []
    for line in open('part_1_pw.txt'):
        currentLine = line.strip().lower().split(":")
        pwData.append((currentLine[0],currentLine[1]))
    
    digestTable = []
    for line in open('possible_passwords.txt'):
        digestTable.append((line.strip().lower(),
        encodeToSHA256(line.strip().lower())))

    # print(pwData)
    # print(digestTable)
    print(batchGuess(pwData, digestTable))
    

if __name__ == "__main__":
    main()

