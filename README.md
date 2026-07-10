
# God Eater Resurrection - SECURE.BIN encrypt/decrypt tool


## DISCLAIMER: Generative AI was used to assist in the RE process and the writing this tool.
## It is, regardless, fully functional. I, Suletta, take full responsibility for any errors in the code.

Reverse-engineered from GER.exe (source file: src\\lib\\denc.c).
The algorithm and key-derivation formula below have been verified against real save data. 
(SECURE.BIN + a live-memory plaintext capture)

# THE CIPHER

  Key  = universal constant (0x8a51891ce32973e4) + RtcHash, as a 64-bit
         addition. RtcHash is 8 bytes, PLAINTEXT offset 0x40.
  Body = only the first (SAVE_SIZE - 8) bytes are actually encrypted. For
         each 256-byte chunk: an LCG (multiplier 0x01000001) drives a
         Fisher-Yates shuffle producing a fresh substitution table, then
         32-bit-word CFB-style XOR chaining, then a per-byte substitution
         offset by the byte's position within the chunk.
  Trailer = the last 8 bytes of the file are NOT ciphertext. They are a
         verbatim, UNENCRYPTED copy of RtcHash, appended after the
         encrypted body. This sits at file offset 0xdb048 and was
         previously misidentified as "RtcHash2, encrypted" - it is neither
         encrypted nor a distinct field. It's just RtcHash again.


Earlier, we assumed the key material was encrypted inside the
save and had to be pulled from a live game session with a
debugger. We were wrong and misidentified the field. In reality the key
seed (RtcHash) is sitting unencrypted in the last 8 bytes of SECURE.BIN. 
In other words, I am a bumbling idiot and the tool can now decrypt any
save file without a debugger or live capture

# USAGE

  Decrypt (key is read automatically from the file's own trailer):  
      ```python3 ger_save_crypto.py decrypt SECURE.BIN output.bin```

  Encrypt (key is derived automatically from RtcHash at offset 0x40):  
      ```python3 ger_save_crypto.py encrypt plain.bin SECURE_new.BIN```

  Encrypt and auto-fix checksums after editing fields:  
      ```python3 ger_save_crypto.py encrypt plain.bin SECURE_new.BIN --fix-checksums```

  Inspect / fix checksums on a plaintext file without encrypting:  
      ```python3 ger_save_crypto.py checksums plain.bin
      python3 ger_save_crypto.py checksums plain.bin --fix plain_fixed.bin```

  Inspect known fields in a plaintext file:  
      ```python3 ger_save_crypto.py info plain.bin```
        
  Port Region (-to dictates arrival, pick the one OPPOSITE of your save, jp or global. Case-sensitive.)  
      ```python3 ger_save_crypto.py port-region --to jp SECURE.BIN output.bin```
      
