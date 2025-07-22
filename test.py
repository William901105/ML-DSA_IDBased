from message_recovery.ml_dsa import ML_DSA_44 as ML_DSA_44_message_recovery
from message_recovery.ml_dsa import ML_DSA_65 as ML_DSA_65_65_message_recovery
from message_recovery.ml_dsa import ML_DSA_87 as ML_DSA_87_message_recovery
from id_based.ml_dsa import ML_DSA_44 as ML_DSA_ID_44_id_based
from id_based.ml_dsa import ML_DSA_65 as ML_DSA_ID_65_id_based
from id_based.ml_dsa import ML_DSA_87 as ML_DSA_ID_87_id_based

import random

security_level = 87


if security_level == 44:
    ML_DSA_message_recovery = ML_DSA_44_message_recovery
    ML_DSA_id_based = ML_DSA_ID_44_id_based
elif security_level == 65:
    ML_DSA_message_recovery = ML_DSA_65_65_message_recovery
    ML_DSA_id_based = ML_DSA_ID_65_id_based
elif security_level == 87:
    ML_DSA_message_recovery = ML_DSA_87_message_recovery
    ML_DSA_id_based = ML_DSA_ID_87_id_based

# test for message recovery
print("Testing ML-DSA with security level %s" % security_level)
pk, sk = ML_DSA_message_recovery.keygen()
recover_byte = ML_DSA_message_recovery.h2_bytes
msg = b"acccccccccccccccccccccccccccccccccccccccddddssssssssssssssssssssssssssssdcccccccccccccccclcq"
print("Message length: %s" % len(msg))
sig = ML_DSA_message_recovery.sign(sk, msg)
print("Signature valid:", ML_DSA_message_recovery.verify(
    pk, msg[recover_byte-2:], sig))

# test for id based
print("Testing ML-DSA ID-based with security level %s" % security_level)
pk, sk = ML_DSA_id_based.keygen()
id = b"test_id"
msg = b"acccccccccccccccccccccccccccccccccccccccddddssssssssssssssssssssssssssssdcccccccccccccccclcq"
print("Message length: %s" % len(msg))
sig = ML_DSA_id_based.sign(sk, msg, id)
print("Signature valid:", ML_DSA_id_based.verify(pk, msg, sig, id))
