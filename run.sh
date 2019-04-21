#sudo ./scanner -i eth0 -pt 70-100 -pu 60-70 195.113.224.36 # localhost 10.0.0.147 pc 80,113,455,82,5000
# macchanger -r -b eth0
sudo valgrind -v --track-origins=yes ./scanner -pt 80,113,443 195.113.224.36 #localhost