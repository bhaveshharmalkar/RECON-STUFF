sudo apt-get update 
sudo apt-get install golang
git clone https://github.com/tomnomnom/assetfinder.git
git clone  https://github.com/tomnomnom/httprobe.git
git clone  https://github.com/blechschmidt/massdns.git
git clone https://github.com/s0md3v/Breacher.git
cd massdns
make
cd bin
mv massdns /usr/local/bin
cd ..
cd ..
cd assetfinder
go build
mv assetfinder /usr/local/bin
cd ..
mv assetfinder /root
mv httprobe /root
mv massdns /root
cd Breacher
chmod +x breacher.py
cd..
mv Breacher /root




