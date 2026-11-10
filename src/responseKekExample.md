Example of deriving the response KEK and wrapping the response CEK.

# Inputs:

transactionID: 2F3C5D7E9A1B4C6D8E0F1A2B3C4D5E6F

KDF (from request KEMRecipientInfo): id-alg-hkdf-with-sha256

wrap (from request KEMRecipientInfo): id-aes256-wrap

Request CEK:
467eb4af44735cdb3121bd89e589dec369f1663f95c4edfae548b85ba8ef5561

Response CEK:
e525c8bfc2d7e54893d1fba2611507de49dfbecc06360a5304fb6001c9d08d75

# Key derivation:
# info = "SCEP-KEM-Response" || transactionID
# KEK = HKDF-SHA256(IKM = Request CEK, salt = <absent>,
#                  info = info, L = 32)

info: 534345502d4b454d2d526573706f6e7365324633433544374539413142344
3364438453046314132423343344435453646

KEK:
abf488f31e6606215fb41e2b5ddb2160f99b4fdf9134e7de136706d083a4c46d

# Outputs:
# encryptedKey = AES-256-KeyWrap(KEK, Response CEK)

encryptedKey: 823563a9a3d5f7e9edf9caf9d5d090205bce75c90452d1bfe8fb3
b3b7d9100af88e37ff31b6cf6d9

# RecipientInfo (kekri), DER:

kekri: a25e02010430220420324633433544374539413142344336443845304631
4132423343344435453646300b060960864801650304012d0428823563a9a3d5f7e
9edf9caf9d5d090205bce75c90452d1bfe8fb3b3b7d9100af88e37ff31b6cf6d9
