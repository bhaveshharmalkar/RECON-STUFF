#!/bin/bash																

n=50
figlet  "RECON-STUFF"
echo $'\t' "// BE THE LATEST VERSION OF YOURSELF //"
echo $'\n'

read -p "SET SCAN NAME {do not provide whitespace} : " NAME
if [[ $NAME = *" "* ]]; 
then
	echo "Error..." 
	echo "Dont give a space while providing the scan name !!!"
	exit
fi
function fd(){
if [ -e /root/Desktop/$NAME ];
then
	echo "Folder is alreday exists !!!"
	echo "Provide a different scan name...."
	exit
	
fi
}
fd

cd /root/Desktop
mkdir $NAME
cd $NAME
a=1
b=1
c=1
d=1
e=1
f=1
g=1
h=1
while (($n > 1))
do
	((n--))
	
	echo $'\n'
	echo "-----------------------------------------------------"
	echo $'\t'"1.  GEO-IP LOCATION"
	echo $'\t'"2.  PING "
	echo $'\t'"3.  NS & MX RECORDS"
	echo $'\t'"4.  WAF DETECTION "
	echo $'\t'"5.  SUBDOMAINS ENUMERATION"
	echo $'\t'"6.  HTTP HEADER, SERVER, LUGINS, LANGUAGE"
	echo $'\t'"7.  VULNERABILITY ANALYSIS"
	echo $'\t'"8.  WORDPRESS SCANNING"
	echo $'\t'"9.  PORT SCANNING"
	echo $'\t'"10. HIDDEN DIR"
	echo $'\t'"11. ONLINE INFO"
	echo $'\t'"12. BUG-BOUNTY RESOURCES"
	echo $'\t'"13. EXIT"
	echo "------------------------------------------------------"
	
	read -p "// Select your choice: " CHOICE

	if [ $CHOICE = 1 ];
	then

		echo $'\n'
		read -p "[#] Enter domain/ip: " URL
		echo "[#] Target $URL"
		show=$(curl http://ip-api.com/json/$URL -s)
		check=$(echo $show | jq '.status' -r)
		if [ $check == "success" ];
		then
			echo "------------------------------"
			country=$(echo $show | jq '.country')
			echo "COUNTRY: $country"
			region=$(echo $show | jq '.regionName' )
			echo "REGION: $region"
			city=$(echo $show | jq '.city')
			echo "CITY: $city"
			latitude=$(echo $show | jq '.lat')
			echo "LATITUDE: $latitude"
			longitude=$(echo $show | jq '.lon')
			echo "LONGITUDE: $longitude"
			isp=$(echo $show | jq '.isp')
			echo "ISP: $isp"
			time=$(echo $show | jq '.timezone')
			echo "Timezone: $time"
			echo "-------------------------------"
			echo "//The location is not perfectly correct,because of server are located in different country.//"
		else
			echo "!!! Error..... !!!"
		fi
			
			
	elif [ $CHOICE = 2 ];
	then	
		echo $'\n'
		read -p "[#] Enter domain/ip: " URL
		echo "[#] Target $URL"
		ping -c 4 $URL
		if [ $? -eq 0 ] 
		then
			echo "----- HOST IS UP -----"
		else
			echo "----- HOST IS DOWN ------" 
		fi

	
					
	elif [ $CHOICE = 3 ];
	then
		
		if [ $a = 1 ];
		then
			mkdir ns_mx
		
		fi
		((a--))
		cd ns_mx
		echo $'\n'
		read -p "[#] Enter domain/ip: " URL
		echo "[#] Target $URL"
		host -t ns $URL > ns_$URL
		host -t mx $URL > mx_$URL	
		cd ..
		echo $'\n'
		echo "***** Output stored in /root/Desktop/$NAME/ns_mx/ns_$URL & /mx_$URL ***** "
		
	elif [ $CHOICE = 4 ];
	then
		echo $'\n'
		
		if [ $b = 1 ];
		then
			mkdir firewall
			
		fi
		((b--))
		cd firewall
		read -p "[#] Enter domain/ip: " URL
		echo "[#] Target $URL"
		
		echo "Proccessing........"
		wafw00f -v $URL > $URL.txt
		echo $'\n'
		echo "***** Output stored in /root/Desktop/$NAME/firewall/$URL.txt *****"
		cd ..
		
	elif [ $CHOICE = 5 ];
	then
		
		echo $'\n'
		if [ $c = 1 ];
		then
			mkdir subdomains
		
		fi
		((c--))
		cd subdomains
		read -p "[#] Enter domain/ip: " URL
		echo "[#] Target $URL"
		
		echo "Extracting...."
		assetfinder $URL -subs-only > $URL.txt
		massdns -r /root/massdns/lists/resolvers.txt -t A -o S $URL.txt -w again_$URL.txt
		sed 's/A.*//' again_$URL.txt | sed 's/CN.*//' | sed 's/\..$//' > 4_$URL.txt
		cat 4_$URL.txt | httprobe > 4_$n.txt
		rm $URL.txt
		rm again_$URL.txt
		rm 4_$URL.txt
		echo $'\n'
		clear
		echo "Scan is done...."
		echo $'\n'
		echo "***** Output stored in /root/Desktop/$NAME/subdomains/4_$n.txt *****" 
		cd ..
		
	elif [ $CHOICE = 6 ];
	then
		echo $'\n' 
		if [ $d = 1 ];
		then
			mkdir webtech
		
		fi
		((d--))
		read -p "[#] Enter domain/ip: " URL
		echo "[#] Target $URL"
	
		echo $'\n'
		echo "-------------------------"
		echo $'\t'"Scan level !!!!!"
		echo $'\t'"1. Normal"
		echo $'\t'"2. Aggresive"
		echo $'\t'"3. Heavy"
		echo "-------------------------"
		read -p "// Select scan level: " LEVEL
		if [ $LEVEL = 1 ];
		then 
			 cd webtech
			 echo "Proccesing...."  
			 whatweb --log-verbose 1_$n -vv $URL 
			 clear
			 echo "Scan is done..."
			 echo $'\n'
			 echo "****** Output stored in /root/Desktop/$NAME/webtech/1_$n ****** " 
			 cd ..
		elif [ $LEVEL = 2 ];
		then
			 cd webtech
			 echo "Proccesing...."  
			 whatweb -a 3 --log-verbose 2_$n -vv $URL
			 clear
			 echo "Scan is done..."
			 echo $'\n'
			 echo "****** Output stored in /root/Desktop/$NAME/webtech/2_$n ******" 
			 cd ..
		elif [ $LEVEL = 3 ];
		then
			 cd webtech
			 echo "Proccesing...."  
			 whatweb -a 4 --log-verbose 3_$n -vv $URL
			 clear
			 echo "Scan is done..."
			 echo $'\n'
			 echo "****** Output stored in /root/Desktop/$NAME/webtech/3_$n ******" 
			 cd ..
		else
			echo "Input Error..."
		fi 
		
	elif [ $CHOICE = 7 ];
	then
		echo $'\n'
		if [ $e = 1 ];
		then
			mkdir scan_vuln
		
		fi
		((e--))
		cd scan_vuln
		read -p "[#] Enter domain/ip: " URL
		echo "[#] Target $URL"
		
		nikto -h $URL -o 6_$URL -F txt
		clear
		echo "Scan is done..."
	        echo $'\n'
		echo "****** Output stored in /root/Desktop/$NAME/scan_vuln/6_$URL"
		cd ..
		
	elif [ $CHOICE = 8 ];
	then 
		
		if [ $f = 1 ];
		then
			mkdir wordpress
		
		fi
		((f--))
		echo $'\n'
		read -p "[#] Enter domain/ip: " URL 
		echo "[#] Target $URL"
		
		read -p "You are conformed that $URL are build on Wordpress (y/n): " WORD
		if [ $WORD = Y ] || [ $WORD = y ];
		then
			echo $'\n'
			echo $'\t'"--------------------------"
			echo $'\t'"Scanning method !!!!"
			echo $'\t'"1. Simple scan"
			echo $'\t'"2. Popular plugins"
			echo $'\t'"3. All plugins"
			echo $'\t'"4. Popular themes"
			echo $'\t'"5. All themes"
			echo $'\t'"6. Vulnerable plugins"
			echo $'\t'"7. Config backups"
			echo $'\t'"---------------------------"
			read -p "// Choose scan: " WORDPRESS
			if [ $WORDPRESS = 1 ];
			then
				cd wordpress
				wpscan -v --url $URL  --enumerate u -o wordpress_1.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/wordpress/wordpress_1.txt *****"
				cd ..
			elif [ $WORDPRESS = 2 ];
			then
				cd wordpress
				wpscan -v --url $URL --enumerate p -o wordpress_2.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/wordpress/wordpress_2.txt *****"
				cd ..
			elif [ $WORDPRESS = 3 ];
			then
				cd wordpress
				wpscan -v --url $URL --enumerate ap -o wordpress_3.txt
			        echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/wordpress/wordpress_3.txt *****"
				cd ..
			elif [ $WORDPRESS = 4 ];
			then
				cd wordpress
				wpscan -v --url $URL  --enumerate t -o wordpress_4.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/wordpress/wordpress_4.txt *****"
				cd ..
			elif [ $WORDPRESS = 5 ];
			then
				cd wordpress
				wpscan -v --url $URL --enumerate at -o wordpress_5.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/wordpress/wordpress_5.txt *****"
				cd ..
			elif [ $WORDPRESS = 6 ];
			then
				cd wordpress
				wpscan -v --url $URL --enumerate vp -o wordpress_6.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/wordpress/wordpress_6.txt *****"
				cd ..
			elif [ $WORDPRESS = 7 ];
			then
				cd wordpress
				wpscan -v --url $URL --enumerate cb -o wordpress_7.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/wordpress/wordpress_7.txt *****"
				cd ..
			else
				echo "Input Error...."
			fi
				
		elif [ $WORD = N ] || [ $WORD = n ];
		then
			echo $'\n'
			echo "// Before you further proceed please conformed it //"
		else
			echo "Input Error...."
		fi	
		
	elif [ $CHOICE = 9 ];
	then
		echo $'\n'
		if [ $g = 1 ];
		then
			mkdir port_scan
		
		fi
		((g--))
		echo $'\t'"-------------------------------------------"
		echo $'\t'"Scanning types !!!!!"
		echo $'\t'"1. Simple ports scan"         
		echo $'\t'"2. Simple verbose scan"      
		echo $'\t'"3. Single or Range of ports"  
		echo $'\t'"4. Full network scan"         
		echo $'\t'"5. Version of services"	  
		echo $'\t'"6. Popular ports"		   
		echo $'\t'"7. Grepable output"          
		echo $'\t'"8. OS fingerprint,detail of each port"      
		echo $'\t'"9. Firewall/IDS spoofing"
		echo $'\t'"-------------------------------------------"
		
		read -p "// Select scan type: " SCAN
		echo $'\n'
		
		if [ $SCAN = 1 ];
		then
			
			cd port_scan
			read -p "[#] Enter domain/ip: " URL
			echo "[#] Target $URL"
			
			nmap $URL > simple_1_$n.txt
			echo "Scanning....."
			echo "Scan is done....."
			echo $'\n'
			echo "***** Output stored in /root/Desktop/$NAME/port_scan/simple_1_$n.txt *****"
			cd ..
		elif [ $SCAN = 2 ];
		then
			cd port_scan
			read -p "[#] Enter domain/ip: " URL
			echo "[#] Target $URL"
		
			echo "Scanning......"
			nmap -vv $URL > simple_verbose_2_$n.txt
			echo "Scan is done....."
			echo $'\n'
			echo "***** Output stored in /root/Desktop/$NAME/port_scan/simple_verbose_2_$n.txt *****"
			cd ..
		elif [ $SCAN = 3 ];
		then 
			cd port_scan
			read -p "[#] Enter domain/ip: " URL
			echo "Example: 80 or 0-1023"
			read -p "Enter port or range: " PORT
			echo "[#] Target $URL for PORT:$PORT"
	
			echo "Scanning....."
			nmap -p$PORT $URL > single_range_3_$n.txt
			echo "Scan is done....."
			echo $'\n'
			echo "***** Output stored in /root/Desktop/$NAME/port_scan/single_range_3_$n.txt *****"
			cd .. 
		elif [ $SCAN = 4 ];
		then
			cd port_scan
			read -p "[#] Enter starting ip: " URL
			echo "ex- 192.168.152.0-255 or 100 as your wish..."
			read -p "Enter last ip: " LAST
			echo "[#] Target $URL scan upto $LAST IP's"
			echo "Scanning....."
			nmap $URL-$LAST > full_net_4_$n.txt
			echo "Scan is done....."
			echo $'\n'
			echo "***** Output stored in /root/Desktop/$NAME/port_scan/full_net_4_$n.txt *****"
			cd .. 
		elif [ $SCAN = 5 ];
		then
			cd port_scan
			read -p "[#] Enter domain/ip: " URL
			echo "[#] Target $URL"
		
			echo "Scanning....."
			nmap -sV $URL > versions_5_$n.txt
			echo "Scan is done....."
			echo $'\n'
			echo "***** Output stored in /root/Desktop/$NAME/port_scan/versions_5_$n.txt *****"
			cd ..
		elif [ $SCAN = 6 ];
		then
			cd port_scan
			read -p "[#] Enter domain/ip: " URL
			echo "[#] Target $URL"
			echo "Scanning....."
			nmap -F $URL > popular_6_$n.txt
			echo "Scan is done....."
			echo $'\n'
			echo "***** Output stored in /root/Desktop/$NAME/port_scan/popular_6_$n.txt *****"
			cd ..
		elif [ $SCAN = 7 ];
		then
			cd port_scan
			read -p "[#] Enter domain/ip: " URL
			echo "[#] Target $URL"
			echo "Scanning....."
			nmap -oG - -vv -sV $URL > grepable_7_$n.txt
			echo "Scan is done....."
			echo $'\n'
			echo "***** Output stored in /root/Desktop/$NAME/port_scan/grepable_7_$n.txt *****"
			cd ..
		elif [ $SCAN = 8 ];
		then
			cd port_scan
			read -p "[#] Enter domain/ip: " URL
			echo "[#] Target $URL"
			echo "Scanning....."
			nmap -A -T4 $URL > os_fingerprint_8_$n.txt
			echo "Scan is done....."
			echo ""
			echo "***** Output stored in /root/Desktop/$NAME/port_scan/os_fingerprint_8_$n.txt *****"
			cd ..
		elif [ $SCAN = 9 ];
		then
			echo $'\n'
			echo $'\t'"----------------------------------------"
			echo $'\t'"Bypass methods !!!!!"
			echo $'\t'"1.  Packet fragmentation (default 8)"    
			echo $'\t'"2.  Packet fragmentation (user defined)"  
			echo $'\t'"3.  Random IP"  
			echo $'\t'"4.  Port spoofing" 
			echo $'\t'"5.  Mac spoofing"   
			echo $'\t'"6.  Data length"    
			echo $'\t'"7.  Bad checksum"   
			echo $'\t'"8.  SYN scan"    
			echo $'\t'"9.  XMAS scan"  
			echo $'\t'"10. Exit" 
			echo $'\t'"----------------------------------------"
			read -p "// Select bypass scanning method: " BYPASS
			echo $'\n'
			
			if [ $BYPASS = 1 ];
			then
				cd port_scan
				
				read -p "[#] Enter domain/ip: " URL
				echo "[#] Target $URL"
				echo "Scanning....."
				nmap -f $URL > packet_fra1_9_1_$n.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/port_scan/packet_fra1_9_1_$n.txt"
				cd ..
			elif [ $BYPASS = 2 ];
			then
				cd port_scan
			
				read -p "[#] Enter domain/ip: " URL
				read -p "Set fragment packet(packet>7 or range of 8): " SET
				echo "[#] Target $URL Fragmentation is $SET"
				echo "Scanning....."
				nmap --mtu $SET $URL > packet_fra2_9_2_$n.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/port_scan/packet_fra2_9_2_$n.txt"
				cd ..
			elif [ $BYPASS = 3 ];
			then
				cd port_scan
				read -p "[#] Enter doamin/ip: " URL
				read -p "Set decoys(decoy>0 or decoy<127): " DECOY
				echo "[#] Target $URL Decoy set is $DECOY"
				echo "Scanning....."
				nmap -D RND:$DECOY $URL > randomip_9_3_$n.txt
				echo "scan done.."
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/port_scan/randomip_9_3_$n.txt"
				cd ..
			elif [ $BYPASS = 4 ];
			then
				cd port_scan
				read -p "[#] Enter domain/ip: " URL
				read -p "Set port: " SET_P
				echo "[#] Target $URL Port:$SET_P"
				echo "Scanning....."
				nmap --source-port $SET_P $URL > port_spoofing_9_4_$n.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/port_scan/port_spoofing_9_4_$n.txt"
				cd ..
			elif [ $BYPASS = 5 ];
			then
				cd port_scan
				read -p "[#] Enter domain/ip: " URL
				echo "[#] Target $URL "
				echo "Scanning....."
				nmap -sT -PN --spoof-mac 0 $URL > mac_spoofing_9_5_$n.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/port_scan/mac_spoofing_9_5_$n.txt"
				cd ..
			elif [ $BYPASS = 6 ];
			then 
				cd port_scan
				read -p "[#] Enter domain/ip: " URL
				read -p "Set data-length(datalength>0 or datalenght<65435): " LENGTH
				echo "[#] Target $URL Data-length of packet: $LENGTH"
				echo "Scanning....."
				nmap --data-length $LENGTH $URL > port_spoofing_9_6_$n.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/port_scan/port_spoofing_9_6_$n.txt"
				cd ..
			elif [ $BYPASS = 7 ];
			then
				cd port_scan
				read -p "[#] Enter domain/ip: " URL
				echo "[#] Target $URL"
				nmap -Pn --badsum $URL > checksum_9_7_$n.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/port_scan/checksum_9_7_$n.txt"
				cd ..
			elif [ $BYPASS = 8 ];
			then
				cd port_scan
				read -p "[#] Enter domain/ip: " URL
				echo "[#] Target $URL"
				echo "Scanning....."
				nmap -sS $URL > syn_scan_9_8_$n.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/port_scan/syn_scan_9_8_$n.txt"
				cd ..
			elif [ $BYPASS = 9 ];
			then
				cd port_scan
				read -p "[#] Enter domain/ip: " URL
				echo "[#] Target $URL"
				echo "Scanning....."
				nmap -sX $URL > xmas_scan_9_9_$n.txt
				echo $'\n'
				echo "***** Output stored in /root/Desktop/$NAME/port_scan/xmas_scan_9_9_$n.txt"
				cd ..	
			elif [ $BYPASS = 10 ];
			then
				echo "__________Thanks for using RECON-STUFF ____________"
				break
			else
				echo "Input Error....."	
			fi
						
		else
			echo "Input Error...."				
			
		fi
	
	elif [ $CHOICE = 10 ];
	then
		echo $'\n'
		echo "This scan take several time :) "
		read -p "If you have a patience then y else n (y/n): " TIME
		if [ $TIME = Y ] || [ $TIME = y ];
		then
			if [ $h = 1 ];
			then
				mkdir hidden
		
			fi
			((h--))
			cd hidden
			echo "You are a great person...."
			echo "USAGE: { http://example.com   or  https://example.com }  "
			echo $'\n'
			read -p "[#] Enter domain: " URL 
			echo "[#] Target $URL"
			dirb $URL | tee $URL.txt
			echo $'\n'
			echo "***** Output stored in /root/Desktop/$NAME/hidden/$URL.txt *****"
			
			cd ..
		elif [ $TIME = N ] || [ $TIME = n ];
		then
			echo "ohh! It's strange..."
		else
			echo "Input Error...."
		fi
			
		
	elif [ $CHOICE = 11 ];
	then
		echo $'\n'
		read -p "[#] Enter domain/ip: " URL
		firefox https://www.virustotal.com/gui/domain/$URL/details      https://sitereport.netcraft.com/?url=$URL    https://whois.domaintools.com/$URL     https://www.robtex.com/dns-lookup/$URL   $URL
		
	
		
	
	elif [ $CHOICE = 12 ];
	then
		echo $'\n'
		echo $'\t'"Resorces!!!!!"
		echo $'\t'"---------------------------"
		echo $'\t'"1.  Web technology" 
		echo $'\t'"2.  Programming langauge"     
		echo $'\t'"3.  Networking"    
		echo $'\t'"4.  Linux"  
		echo $'\t'"5.  Learn vulnerability"      
		echo $'\t'"6.  Android security"     
		echo $'\t'"7.  Bug-bounty writeups"    
		echo $'\t'"8.  Practise labs"  
		echo $'\t'"9.  Maps" 
		echo $'\t'"10. Git-hub for bugbounty"  
		echo $'\t'"11. You-Tube Channels"
		echo $'\t'"12. Books"
		echo $'\t'"13. Exit"
		echo $'\t'"----------------------------"
		
		read -p "// Select your choice:  " LEARN
		
		if [ $LEARN = 1 ];
		then
			firefox https://www.tutorialspoint.com/http/index.htm  
		
		elif [ $LEARN = 2 ];
		then
			firefox  https://www.w3schools.com/    
		
		elif [ $LEARN = 3 ];
		then
			echo $'\n'
			echo $'\t'"----------------------"
			echo $'\t'"1. Beginner level"
			echo $'\t'"2. Intermediate level"
			echo $'\t'"3. Exit"
			echo $'\t'"----------------------"
			read -p "// Select level: " YOUR
			if [ $YOUR = 1 ];
			then
				firefox  https://commotionwireless.net/docs/cck/networking/learn-networking-basics/  
			elif [ $YOUR = 2 ];
			then
				firefox   https://www.geeksforgeeks.org/computer-network-tutorials/  
			elif [ $YOUR = 3 ];
			then
				
				break
			else
				echo "Input Error...."
			fi
		
		elif [ $LEARN = 4 ];
		then
			firefox  http://linuxcommand.org/index.php 
		
		elif [ $LEARN = 5 ];
		then
			echo $'\n'
			echo $'\t'"------------------------------------"
			echo $'\t'"1. XSS.CSRF"
			echo $'\t'"2. Basics of all vulnerabilities"
			echo $'\t'"3. Approach of vulnerability"
			echo $'\t'"------------------------------------"
			read -p "// Select choice: " VULN

			if [ $VULN = 1 ];
			then
				firefox  http://www.geekboy.ninja/blog/   
			elif [ $VULN = 2 ];
			then
				firefox  https://www.hacksplaining.com/lessons  
			elif [ $VULN = 3 ];
			then
				firefox   https://www.apriorit.com/dev-blog/622-qa-web-application-pen-testing-owasp-checklist   
			else 
				echo "Input Error..."
			fi
			
		elif [ $LEARN = 6 ];
		then
			firefox  https://appsecwiki.com/mobilesecurity    
		
		elif [ $LEARN = 7 ];
		then
			firefox  https://pentester.land/list-of-bug-bounty-writeups.html
		
		elif [ $LEARN = 8 ];
		then
			firefox  https://portswigger.net/web-security 
		
		elif [ $LEARN = 9 ];
		then
			firefox  https://www.amanhardikar.com/mindmaps/Practice.html
		
		elif [ $LEARN = 10 ];
		then
			echo $'\n'
			echo $'\t'"Github Repository!!!!!"
			echo $'\t'"---------------------------------"
			echo $'\t'"1. How to start,blogs,writeup "   
			echo $'\t'"2. Resources "	 	 
			echo $'\t'"3. Basic Approach "	
			echo $'\t'"4. Bugbounty Programs"        	
			echo $'\t'"5. Payloads"  
			echo $'\t'"6. Exit"  
			echo $'\t'"---------------------------------"
			read -p "// Select choice: " GIT
			if [ $GIT = 1 ];
			then
				firefox  https://github.com/djadmin/awesome-bug-bounty 
			elif [ $GIT = 2 ];
			then
				firefox  https://github.com/nahamsec
			elif [ $GIT = 3 ];
			then
				firefox   https://github.com/sehno/Bug-bounty/find/master
			elif [ $GIT = 4 ];
			then
				firefox  https://github.com/disclose/
			elif [ $GIT = 5 ];
			then
				firefox  https://github.com/swisskyrepo/PayloadsAllTheThings  
			elif [ $GET = 6 ];
			then

				break
				
			else
				echo "Input Error...."
			fi
		elif [ $LEARN = 11 ];
		then
			echo $'\n'
			echo $'\t'"You-Tube!!!!"
			echo $'\t'"---------------------------"
			echo $'\t'"1. Programming Language"
			echo $'\t'"2. Cyber Security"
			echo $'\t'"---------------------------"
			read -p "// Select choice: " TUBE
			if [ $TUBE = 1 ];
			then
				echo $'\n'
				echo $'\t'"-------------------------"
				echo $'\t'"1. Code-With-Harry"
				echo $'\t'"2. Telusko"
				echo $'\t'"3. Clever Programmer"
				echo $'\t'"-------------------------"
				read -p "// Select channel: " CWH
				if [ $CWH = 1 ];
				then
					firefox  https://www.youtube.com/channel/UCeVMnSShP_Iviwkknt83cww
				elif [ $CWH = 2 ];
				then
					firefox  https://www.youtube.com/channel/UC59K-uG2A5ogwIrHw4bmlEg
				elif [ $CWH = 3 ];
				then
					firefox  https://www.youtube.com/channel/UCqrILQNl5Ed9Dz6CGMyvMTQ
				else
					echo "Input Error...."
				fi
			elif [ $TUBE = 2 ];
			then
				echo $'\n'
				echo $'\t'"---------------------------"
				echo $'\t'"1. Bitten Tech"
				echo $'\t'"2. Spin The Hack"
				echo $'\t'"3. The cyber Expert"
				echo $'\t'"4. Tech Chip"
				echo $'\t'"5. Technical navigator"
				echo $'\t'"6. Geeky Hub"
				echo $'\t'"7. Hackersploit"
				echo $'\t'"8. Stok"
				echo $'\t'"9. The Cyber Mentor "
				echo $'\t'"---------------------------"
				read -p "// Select channel: " HACK
				if [ $HACK = 1 ];
				then
					firefox  https://www.youtube.com/bittentech
				elif [ $HACK = 2 ];
				then
					firefox  https://www.youtube.com/spinthehack
				elif [ $HACK = 3 ];
				then
					firefox  https://www.youtube.com/results?search_query=the+cyber+expert
				elif [ $HACK = 4 ];
				then
					firefox  https://www.youtube.com/channel/UCYS9sTrPpcIVDxz2yVPbuLw
				elif [ $HACK = 5 ];
				then
					firefox  https://www.youtube.com/channel/UClPH8tL-fWX1rqTTegkTNZw
				elif [ $HACK = 6 ];
				then
					firefox  https://www.youtube.com/geekyhub
				elif [ $HACK = 7 ];
				then
					firefox  https://www.youtube.com/hackersploit
				elif [ $HACK = 8 ];
				then
					firefox  https://www.youtube.com/channel/UCQN2DsjnYH60SFBIA6IkNwg
				elif [ $HACK = 9 ];
				then
					firefox  https://www.youtube.com/channel/UC0ArlFuFYMpEewyRBzdLHiw  
				else
					echo "Input Error...."
				fi
			else
				echo "Input Error..."
			fi
			
		elif [ $LEARN = 12 ];
		then
			echo $'\n'
			echo $'\t'"Books !!!!"
			echo $'\t'"-----------------------------------------"
			echo $'\t'"1. Web Application Hackers Handbook"  
			echo $'\t'"2. Web Hacking 101"  
			echo $'\t'"3. Mastering Modern Web Penetration Testing" 
			echo $'\t'"4. Penetration testing - Hands on Introduction to hacking"
			echo $'\t'"5. Hacker Playbook 2" 
			echo $'\t'"6. Hacker Playbook 3" 
			echo $'\t'"7. Black Hat Python" 
			echo $'\t'"8. Python for Offensive Pentest"
			echo $'\t'"------------------------------------------"
			read -p "choose book: " BK
			if [ $BK = 1 ];
			then
				firefox  http://index-of.es/EBooks/11_TheWeb%20Application%20Hackers%20Handbook.pdf
			elif [ $BK = 2 ];
			then
				firefox  http://index-of.es/Miscellanous/LIVRES/web-hacking-101.pdf
			elif [ $BK = 3 ];
			then
				firefox  https://lira.epac.to/DOCS-TECH/Hacking/Modern%20Web%20Penetration%20Testing%202016.pdf
			elif [ $BK = 4 ];
			then
				firefox  https://repo.zenk-security.com/Magazine%20E-book/Penetration%20Testing%20-%20A%20hands-on%20introduction%20to%20Hacking.pdf
			elif [ $BK = 5 ];
			then
				firefox   http://index-of.es/Varios-2/The%20Hacker%20Playbook%202.pdf
			elif [ $BK = 6 ];
			then
				firefox   https://darkweblinks.org/files/Books/The%20Hacker%20Playbook%20-%20Practical%20Guide%20To%20Penetration%20Testing.pdf
			elif [ $BK = 7 ];
			then
				firefox   https://olinux.net/wp-content/uploads/2019/01/python.pdf
			elif [ $BK = 8 ];
			then
				firefox  https://bit.ly/36QKWxS
			else
				echo "Input Error..."
			fi
			
			
		elif [ $LEARN = 13 ];
		then
			
			break
		else
			echo "Input Error...."
		fi		
		
	elif [ $CHOICE = 13 ];
	then
		echo $'\n'
		echo $'\t' "    _______ THANKS FOR USING RECON-STUFF __________ "
		
		break

	else
		echo $'\n'
		echo "Error occured..."
		echo "--- Please enter valid input ---"
				
	fi
done






