# Gare-du-Nord
## Running the code using the virtualbox vm that we provide
If you have a hold of the virtualbox VM, running the experiment is
straightforward:
1. Open up the VM in virtualbox and login using the credentials mininet:mininet.
   From here, enter the command `startx` to start the GUI. This should bring you
   to an lxde session.
2. Open up a terinal program like xterm or lxterminal and navigate to Gare-du-Nord/mininet. 
   Run the mininet topology
   with `sudo python tcp_desync.py`. This should set up the topology, including
   the telnet server on h1 and the attacker script on h3, then get you
   to the mininet CLI. This also starts automatic tcpdumps for h1 and h3 that
   will capture all the packets that they see into files named h1dump.pcap and
   h3dump.pcap.
4. From the mininet CLI, run `h2 telnet h1`. If you want to actually use the
   telnet sesstion, use mininet:mininet as the credentials. Note that you will see duplicate input,
   this is normal and due to the way the cli and telnet handle text. If not, then Ctrl+C
   to stop the connection, then Ctrl+d or entering `exit` will get you out of
   the mininet CLI. 
5. The file scapy.log is a log produced by the attacker script that shows what
   was done by it.
6. Finally, to view the captures for the exchange, you can either use tcpdump
   with `tcpdump -r h1dump.pcap` or wireshark with `sudo wireshark h1dump.pcap`
7. CLEANUP: If you want to run the experiment again, it is recommended that you
   delete the pcap files as well as the scapy.log.
## Running the python code for the simulation
This is a separate step to the above as described in the final report. It is
meant as a showcasee of the attack within a fully simulated environment.
1. Open up the VM and login with the credentials mininet:mininet
2. Open a terminal emulator like xterm or lxterminal and navigate to Gare-du-Nord/       
3. Run the python script with `python simulation.py`
