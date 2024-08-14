# padding-oracle-attack

## Summercourse assignment

- Use http://blowfish.online-domain-tools.com
- Set Input Text (HEX) – ff ac e9 cc 09 2e da e6  (ciphertext) 
- Set Key – “very very secret key”
- Set Cipher – BLOWFISH and mode - CBC
- Change Init. Vector accordingly to obtain values after decryption
- (applying padding oracle attack)
  - Xx xx xx xx xx xx xx 01 (Hex)
  - Xx xx xx xx xx xx 02 02 (Hex)
  - Etc...

Send here all changed Init. Vectors

### Necessary packages
`pip install pycryptodome`

