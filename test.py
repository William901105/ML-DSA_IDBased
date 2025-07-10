from dilithium_py.ml_dsa import ML_DSA_44
from dilithium_py.ml_dsa import ML_DSA_65
from dilithium_py.ml_dsa import ML_DSA_87
import random

security_level = 44


if security_level == 44:
    ML_DSA = ML_DSA_44
elif security_level == 65:
    ML_DSA = ML_DSA_65
elif security_level == 87:
    ML_DSA = ML_DSA_87

pk, sk = ML_DSA.keygen()
recover_byte = ML_DSA.h2_bytes
msg = b"acccccccccccccccccccccccccccccccccccccccddddssssssssssssssssssssssssssssdcccccccccccccccclcq"
print("Message length: %s" % len(msg))
sig = ML_DSA.sign(sk, msg)
print("Signature valid:", ML_DSA.verify(pk, msg[recover_byte-2:], sig))
