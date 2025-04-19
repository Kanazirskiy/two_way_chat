# two_way_chat

python3 twoway.py --bind "0.0.0.0:port" 
  --sig-cer for-signature.cer 
  --sig-key for-signature.prv 
  --kem-cer for-key-agreement.cer 
  --kem-key for-key-agreement.prv 
  --trusted-sig trusted-sig.txt   
  --trusted-kem trusted-kem.txt

python3 ../twoway.py --connect "IPv4:port" 
  --sig-cer for-signature.cer 
  --sig-key for-signature.prv 
  --kem-cer for-key-agreement.cer 
  --kem-key for-key-agreement.prv 
  --trusted-sig trusted-sig.txt   
  --trusted-kem trusted-kem.txt
