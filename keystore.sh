#!/bin/bash


echo -e "\nCA Certificate"
keytool -genkeypair -keyalg RSA -keysize 2048 -validity 360 -alias ca -dname "CN=CA, O=zencilerTrust, C=TR" -keystore keyStore_CA  -storepass samilyunus  -keypass samilyunus
keytool -exportcert -rfc -alias ca -keystore keyStore_CA -storepass samilyunus > certificateAuth.cer

echo -e "\nServer's Certificate"
keytool -genkeypair -keyalg RSA -keysize 2048 -validity 360 -alias server -dname "CN=SERVER, O=zencilerTrust, C=TR" -keystore keyStore_Server -storepass samilyunus  -keypass samilyunus
keytool -certreq -alias server -storepass samilyunus -keystore keyStore_Server | keytool  -gencert -alias ca -rfc -keystore keyStore_CA -storepass samilyunus > server.cer
cat certificateAuth.cer | keytool -importcert -alias ca -noprompt -keystore keyStore_Server -storepass samilyunus
cat certificateAuth.cer server.cer | keytool -importcert -alias server -keystore keyStore_Server -storepass samilyunus

echo -e "\nClients's Certificate"
keytool -genkeypair -keyalg RSA -keysize 2048 -validity 360 -alias client -dname "CN=CLIENT, O=zencilerTrust, C=TR" -keystore keyStore_Client -storepass samilyunus  -keypass samilyunus
keytool -certreq -alias client -keystore keyStore_Client -storepass samilyunus | keytool -gencert -alias ca -rfc -keystore keyStore_CA -storepass samilyunus > client.cer
cat certificateAuth.cer | keytool -importcert -alias ca -noprompt -keystore keyStore_Client -storepass samilyunus
cat certificateAuth.cer client.cer | keytool -importcert -alias client -keystore keyStore_Client -storepass samilyunus

echo -e "\nfinished"
