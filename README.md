# two_way_chat
Безопасный чат на двоих

## Генерация самоподписанных сертификатов для тестирования
python3 generate_selfsigned_cert.py  
  --sig-cer sig_cer.cer  
  --sig-key sig_key.prv  
  --kem-cer kem_cer.cer  
  --kem-key kem_key.prv

## Пополнение доверенных хэшей сертификатов
python3 add_trusted.py  
  --sig-cer sig_cer.cer  
  --kem-cer kem_cer.cer 


## Зависимости

- [pygost](http://www.pygost.cypherpunks.su/)
- [pyderasn](http://www.pyderasn.cypherpunks.su/)


## Пример запуска программы
python3 twoway.py --bind "0.0.0.0:port" 
  --sig-cer for-signature.cer 
  --sig-key for-signature.prv 
  --kem-cer for-key-agreement.cer 
  --kem-key for-key-agreement.prv 
  --trusted-sig trusted-sig.txt   
  --trusted-kem trusted-kem.txt

python3 twoway.py --connect "IPv4:port" 
  --sig-cer for-signature.cer 
  --sig-key for-signature.prv 
  --kem-cer for-key-agreement.cer 
  --kem-key for-key-agreement.prv 
  --trusted-sig trusted-sig.txt   
  --trusted-kem trusted-kem.txt
