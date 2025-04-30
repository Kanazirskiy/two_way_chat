# two_way_chat
Безопасный чат на двоих


## Зависимости

- [pygost](http://www.pygost.cypherpunks.su/)
- [pyderasn](http://www.pyderasn.cypherpunks.su/)


## Пример запуска программы
python3 twoway-chat.py --bind "0.0.0.0:port"  
  --sig-cer for-signature.cer  
  --sig-key for-signature.prv  
  --kem-cer for-key-agreement.cer  
  --kem-key for-key-agreement.prv  
  --trusted-sig trusted-sig   
  --trusted-kem trusted-kem

python3 twoway-chat.py --connect "IPv4:port"   
  --sig-cer for-signature.cer  
  --sig-key for-signature.prv  
  --kem-cer for-key-agreement.cer  
  --kem-key for-key-agreement.prv  
  --trusted-sig trusted-sig    
  --trusted-kem trusted-kem
