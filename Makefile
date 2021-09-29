fetch_rules:
	curl "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt" > rules1.txt
	curl "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt" > rules2.txt

	curl "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/win-spy.txt" > windows.txt
	curl "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/win-extra.txt" >> windows.txt

	curl "https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/xiaomi" > privacy.txt
	curl "https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/huawei" >> privacy.txt
	curl "https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/samsung" >> privacy.txt
	curl "https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/windows" >> privacy.txt
	curl "https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/alexa" >> privacy.txt

	curl "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-social/hosts" > tmp.rules.txt
	sed 's/^0\.0\.0\.0 //g' tmp.rules.txt > tmp.rules2.txt
	tail -n +37 tmp.rules2.txt > rules.txt

clean:
	rm -rf *.txt
