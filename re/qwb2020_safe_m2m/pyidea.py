def mul(x, y):
    isValueCorrect(x)
    isValueCorrect(y)

    if x == 0:
        x = 0x10000
    if y == 0:
        y = 0x10000

    result = (x * y) % 0x10001 # 17 in binary

    if result == 0x10000:
        result = 0

    isValueCorrect(result)
    return result

def mulInverse(x):
    if x <= 1:
        return x
    y = 0x10001
    t0 = 1
    t1 = 0
    while True:
        t1 += ((int)(y / x) * t0)
        y %= x
        if (y == 1):
            return (1 - t1) & 0xffff
        t0 += ((int)(x / y) * t1)
        x %= y
        if (x == 1):
            return t0

def addInverse(x):
    return (0x10000 - x) & 0xFFFF


def isValueCorrect(val):
    assert 0 <= val <= 0xFFFF

def isInputCorrect(inputs):
    for input in inputs:
        assert 0 <= input <= 0xFFFF

def isKeysCorrect(keys):
    for key in keys:
        assert 0 <= key <= 0xFFFF

def isKeyLengthCorrect(key):
    assert 0 <= key < (1 << 128)

def isInputTextCorrect(text):
    assert 0 <= text < (1 << 64)

def splitInputText(text):
    x1 = (text >> 48) & 0xFFFF
    x2 = (text >> 32) & 0xFFFF
    x3 = (text >> 16) & 0xFFFF
    x4 = text & 0xFFFF
    return x1, x2, x3, x4

def firstFourSteps(x1, x2, x3, x4, keys):
    isInputCorrect([x1, x2, x3, x4])
    isKeysCorrect(keys)

    key1 = keys[0]
    key2 = keys[1]
    key3 = keys[2]
    key4 = keys[3]


    out1 = mul(x1, key1)
    out2 = (x2 + key2) % 0x10000
    out3 = (x3 + key3) % 0x10000 # 16 in binary
    out4 = mul(x4, key4)

    return out1, out2, out3, out4

def restOfTheSteps(y1, y2, y3, y4, keys):
    isInputCorrect([y1, y2, y3, y4])
    isKeysCorrect(keys)

    key5 = keys[4]
    key6 = keys[5]

    step5 = y1 ^ y3
    step6 = y2 ^ y4

    step7 = mul(step5, key5)
    step8 = (step6 + step7) % 0x10000
    step9 = mul(step8, key6)
    step10 = (step7 + step9) % 0x10000

    x1 = y1 ^ step9
    x2 = y2 ^ step10
    x3 = y3 ^ step9
    x4 = y4 ^ step10

    return x1, x2, x3, x4

class IdeaAlgorithm:
    def __init__(self, key):
        self.keys = None
        self.inverseKeys = None
        self.configureKey(key)
        self.configureInverseKey()

    def configureKey(self, key):
        isKeyLengthCorrect(key)
        modulus = 1 << 128 # shift by 128 bits

        subKeys = []
        for i in range(54): # 54 number of needed keys
            subKeys.append((key >> (112 - 16 * (i % 8))) % 0x10000) #generate subkeys
            if i % 8 == 7:
                key = ((key << 25) | (key >> 103)) % modulus

        allGenerateKeys = []
        for i in range(9):
            singleRoundKeys = subKeys[6 * i: 6 * (i + 1)]
            allGenerateKeys.append(tuple(singleRoundKeys))
        self.keys = tuple(allGenerateKeys)

    def configureInverseKey(self):
        inverseKeysTmp = [[0 for x in range(6)] for y in range(9)]
        keysTmp = self.keys

        inverseKeysTmp[8][0] = mulInverse(keysTmp[0][0])
        inverseKeysTmp[8][1] = addInverse(keysTmp[0][1])
        inverseKeysTmp[8][2] = addInverse(keysTmp[0][2])
        inverseKeysTmp[8][3] = mulInverse(keysTmp[0][3])

        p = 0
        for i in range(7, 0,  -1):
            inverseKeysTmp[i][4] = keysTmp[p][4]
            inverseKeysTmp[i][5] = keysTmp[p][5]
            inverseKeysTmp[i][0] = mulInverse(keysTmp[p+1][0])
            inverseKeysTmp[i][2] = addInverse(keysTmp[p+1][1])
            inverseKeysTmp[i][1] = addInverse(keysTmp[p+1][2])
            inverseKeysTmp[i][3] = mulInverse(keysTmp[p+1][3])
            p = p + 1

        inverseKeysTmp[0][4] = keysTmp[7][4]
        inverseKeysTmp[0][5] = keysTmp[7][5]
        inverseKeysTmp[0][0] = mulInverse(keysTmp[8][0])
        inverseKeysTmp[0][1] = addInverse(keysTmp[8][1])
        inverseKeysTmp[0][2] = addInverse(keysTmp[8][2])
        inverseKeysTmp[0][3] = mulInverse(keysTmp[8][3])


        self.inverseKeys = inverseKeysTmp

    def encrypt(self, plaintext):
        isInputTextCorrect(plaintext)

        x1, x2, x3, x4 = splitInputText(plaintext)

        for i in range(8):
            singleRoundKey = self.keys[i]

            y1, y2, y3, y4 = firstFourSteps(x1, x2, x3, x4, singleRoundKey)
            x1, x2, x3, x4 = restOfTheSteps(y1, y2, y3, y4, singleRoundKey)

            x2, x3 = x3, x2

        y1, y2, y3, y4 = firstFourSteps(x1, x3, x2, x4, self.keys[8]) # last half round

        outputCipherText = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return outputCipherText

    def decrypt(self, plaintext):
        isInputTextCorrect(plaintext)

        x1, x2, x3, x4 = splitInputText(plaintext)

        for i in range(8):
            singleRoundKey = self.inverseKeys[i]

            y1, y2, y3, y4 = firstFourSteps(x1, x2, x3, x4, singleRoundKey)
            x1, x2, x3, x4 = restOfTheSteps(y1, y2, y3, y4, singleRoundKey)

            x2, x3 = x3, x2

        y1, y2, y3, y4 = firstFourSteps(x1, x3, x2, x4, self.inverseKeys[8]) # last half round

        outputCipherText = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return outputCipherText



