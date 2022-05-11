from base64 import encode
from concurrent.futures import thread
from copy import copy
from ctypes.wintypes import tagRECT
from fileinput import filename
import hashlib
import binascii
from hmac import digest
from threading import Thread
import math
import time
from unittest import result

def encodeToSHA256(plain):
    encoded_password = plain.encode('utf-8')
    hasher = hashlib.sha256(encoded_password)
    digest = hasher.digest() # type=bytes
    digest_as_hex = binascii.hexlify(digest)
    return digest_as_hex.decode('utf-8')

def batchGuess(data, references, note, filename):
    global SUCCESS_CRACKS
    totalLen = len(data)
    print("["+note+"]"+"got file with "+str(totalLen)+" entries\n")

    counter = 0
    for point in data:
        counter += 1
        if counter%40 == 0:
            print("["+note+"]"+"did "+str(int(counter/totalLen*100))+"%\n")
        username = point[0]
        hashedPW = point[1]

        refFile = open(references,"r")
        # print("testing "+username)
        for possibility in refFile:
            # if(SUCCESS_CRACKS==200):
            #     break
            current_line = possibility.strip().lower().split(",")
            # print(current_line)
            PossiblePW = current_line[0].strip()
            hashedPossiblePW = current_line[1].strip()
            # print("testing "++"\nagainst possibility"+hashedPossiblePW)
            if hashedPossiblePW == hashedPW:
                SUCCESS_CRACKS = SUCCESS_CRACKS+1
                writtenString = username+":"+PossiblePW+"\n"
                print("hit # "+str(SUCCESS_CRACKS)+" = "+writtenString)
                f = open(filename, "a")
                f.write(writtenString)
                f.close()
                # results.append((username,PossiblePW))
                break
        refFile.close()

def multiThreadBatchGuess(data, references, howManyThreads, filename):
    totalLen = len(data)
    dataPartitionSize = int(math.ceil(totalLen/howManyThreads))

    allThreads = []
    
    for i in range(0,totalLen,dataPartitionSize):
        specialNote = "_MultiThread_"+str(int(i/dataPartitionSize))
        newThread = Thread(target=batchGuess,args=(data[i:i+dataPartitionSize],references,specialNote,filename))
        allThreads.append(newThread)
    
    for t in allThreads:
        t.start()

    for t in allThreads:
        t.join()

def decode(pwFilename, potentialPWFilename, resultsFilename):
    start = time.time()
    pwData = []

    global SUCCESS_CRACKS
    SUCCESS_CRACKS = 0

    print("loading password sourcefile")
    for line in open(pwFilename):
        currentLine = line.strip().lower().split(":")
        pwData.append((currentLine[0],currentLine[1]))

    print("hashing guesses")
    startHashing = time.time()
    digestTable = []

    hasherFilename = "resultsFilename"[:-4]+"_hashes.txt"
    hasherFile = open(hasherFilename,"w")
    hasherFile.write("")
    hasherFile.close

    counter = 0
    hasherFile = open(hasherFilename,"a")
    for line in open(potentialPWFilename):
        counter+=1
        # (line.strip().lower(),encodeToSHA256(line.strip().lower()))
        hasherFile.write(line.strip().lower()+","+encodeToSHA256(line.strip().lower())+"\n")
    endHashing = time.time()
    totalHashTime = endHashing-startHashing

    howManyPWs = len(pwData)
    howManyHashes = counter

    #delete all entries
    f = open(resultsFilename, "w")
    f.write("")
    f.close()
    
    #get metrics
    startGuessing = time.time()

    #start guessing
    print("start guessing...")
    multiThreadBatchGuess(pwData,hasherFilename,36,resultsFilename)
    endWholeProgram = time.time()
    guessTimeTaken = endWholeProgram-start
    timeTaken = endWholeProgram-start
    
    #print results
    print("HOW MANY HASHES: "+str(howManyHashes))
    print("HOW MANY PWs loaded: "+str(howManyPWs))
    print("HOW MANY PWs cracked: "+str(SUCCESS_CRACKS))
    print("seconds per hash: "+str(totalHashTime/howManyHashes)+" seconds")
    print("seconds per password cracked: "+str(guessTimeTaken/SUCCESS_CRACKS)+" seconds")
    print("crackedPW/Hash: "+str(SUCCESS_CRACKS/howManyHashes))

def verbatimGuess(pwFilename,potentialPWFilename,resultsFilename):
    global SUCCESS_CRACKS
    pwToBeCracked = open(pwFilename,"r")
    for line in pwToBeCracked:
        current = line.strip().lower().split(":")
        hashedPW = current[1]
        username = current[0]
        print("guessing "+username)
        ref = open(potentialPWFilename,"r")
        firstPWCounter = 0
        for line2 in ref:
            print(line2)
            pw = line2.strip().lower()
            # print("guessing pw = ["+pw+"]")
            if firstPWCounter == 0:
                firstPWCounter+=1
                hashedPotentialPW = encodeToSHA256(pw)
                # print("hpw="+hashedPW)
                # print("ppw="+hashedPotentialPW)
                if hashedPW == hashedPotentialPW:
                    f = open(resultsFilename,"a")
                    f.write(username+":"+pw)
                    SUCCESS_CRACKS+=1
                    print("hit # "+str(SUCCESS_CRACKS)+" = "+(username+":"+pw))
                    f.close()
                    break
            else:
                firstPWCounter+=1
                refDup1 = open(potentialPWFilename,"r")
                for line3 in refDup1:
                    pwPt2 = line3.strip().lower()
                    pwConcat = pw+pwPt2
                    # print("guessing pw = ["+pwConcat+"]")
                    hashedPotentialPW = encodeToSHA256(pwConcat)
                    if hashedPW == hashedPotentialPW:
                        f = open(resultsFilename,"a")
                        f.write(username+":"+pwConcat)
                        SUCCESS_CRACKS+=1
                        print("hit! # "+str(SUCCESS_CRACKS)+" = "+(username+":"+pwConcat))
                        f.close()
                        break
        ref.close()

def verbatimGuessPt3(pwFilename,potentialPWFilename,resultsFilename):
    f = open(resultsFilename,"w")
    f.write("")
    f.close()
    global SUCCESS_CRACKS
    pwToBeCracked = open(pwFilename,"r")
    for line in pwToBeCracked:
        current = line.strip().lower().split(":")
        username = current[0]
        pwString = current[1]
        hashedPW = pwString[3:]
        pwSalt = hashedPW[:8]
        for line2 in open(potentialPWFilename,"r"):
            startHashing = time.time()
            trialPWString = line2.strip().lower()
            saltCocatPW = pwSalt+trialPWString
            saltedHash = encodeToSHA256(saltCocatPW)
            finalTentativePW = "$5$"+pwSalt+"$"+saltedHash
            endHashingTime = time.time()
            totalTimeHashing = str(startHashing - endHashingTime)
            if finalTentativePW == pwString:
                hit = username+":"+trialPWString
                f = open(resultsFilename,"a")
                f.write(hit)
                f.close()
                print(hit)
    print("hashing time:"+totalTimeHashing)
            

def decodePt2(pwFilename, potentialPWFilename, resultsFilename):
    start = time.time()

    global SUCCESS_CRACKS
    SUCCESS_CRACKS = 0

    #delete all entries
    f = open(resultsFilename, "w")
    f.write("")
    f.close()
    
    #get metrics
    startGuessing = time.time()

    #start guessing
    print("start guessing...")
    verbatimGuess(pwFilename, potentialPWFilename, resultsFilename)
    endWholeProgram = time.time()
    guessTimeTaken = endWholeProgram-start
    
    #print results
    print("HOW MANY PWs cracked: "+str(SUCCESS_CRACKS))

def multiThreadBatchMakeDouble(newFilename, howManyThreads):

    allPossiblePWs = open(newFilename, "w")
    allPossiblePWs.write("")
    allPossiblePWs.close()
    allPWPossibilities = [line.strip().lower() for line in open("possible_passwords_p1.txt","r")]
    totalLen = len(allPWPossibilities)
    dataPartitionSize = int(math.ceil(totalLen/howManyThreads))

    allThreads = []

    for i in range(0,totalLen,dataPartitionSize):
        specialNote = str(int(i/dataPartitionSize)+1)
        newThread = Thread(target=makeDouble,args=(allPWPossibilities[i:i+dataPartitionSize],newFilename,"makeDouble thread "+specialNote))
        allThreads.append(newThread)
    
    for t in allThreads:
        t.start()

    for t in allThreads:
        t.join()
    return newFilename

def makeDouble(data,newFilename,notes):
    howMuchData =  len(data)
    print("["+notes+"]"+"got entries: "+str(howMuchData))

    #CHANGE THIS TO ALTER DATA SIZE.
    #CHANGE THIS TO ALTER DATA SIZE.
    #CHANGE THIS TO ALTER DATA SIZE.
    sizeDivisor = 8

    allPossiblePWs = open(newFilename, "a")
    counter1 = 0
    for firstWord in data:
        
        if counter1%250==0:
            print("["+notes+"]"+"complete: "+str(int(counter1*sizeDivisor/howMuchData*100))+"%")
        counter1 +=1
        newPW1 = firstWord.strip().lower()
        allPossiblePWs.write(newPW1+"\n")

        allPWFile2 = data
        counter2 = 0
        for secondWord in allPWFile2:
            if counter2%sizeDivisor!=0:
                counter2 +=1
                continue
            if counter2>howMuchData/sizeDivisor:
                break
            counter2 +=1
            newPW2 = secondWord.strip().lower()
            allPossiblePWs.write(newPW1+newPW2+"\n")
    
    allPossiblePWs.close()
    print("finished making file for pws.")
    return newFilename

def main():
    start = time.time()
    # decode("part_1_pw.txt","possible_passwords_p1.txt", "part_1_results.txt")\
    # decode("part_2_pw.txt",multiThreadBatchMakeDouble("pt2PotentialPWs.txt",36), "cracked2.txt")
    # decode("part_2_pw.txt","pt2PotentialPWs.txt", "cracked2.txt")
    # decodePt2("part_1_pw.txt","possible_passwords_p1.txt", "part_1_pt2_results.txt")
    # decodePt2("jondich.txt","moose.txt", "part_1_pt2_results.txt")
    # verbatimGuessPt3("jondich_pt3.txt","moose.txt","cracked3.txt")
    endWholeProgram = time.time()
    timeTaken = endWholeProgram-start
    print("TOTAL TIME TAKEN: "+str(timeTaken)+" seconds")

if __name__ == "__main__":
    main()
    

