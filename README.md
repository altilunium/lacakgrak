# lacakgrak
Simple inbound/outbound packet sniffer

![image](https://github.com/user-attachments/assets/28df2a1b-c60c-4742-8f01-b2d83c841af5)

* Statistics will be updated each 10 seconds
* For each IP, sorted by transferred byte size

### Background
This sniffer is so simplified that you can only see the size of the traffic. This is because I just want to know where my traffic is going and how big it is. I want to identify the cause of my recent unexpected surge in internet traffic.

### Installation
```
pip install scapy
pip install clipboard
```

### Usage
```
python a.py
```
Press Ctrl+C to quit (the statistics will be copied to the clipboard).

### Release Notes
#### v24.8.16
* Ctrl + C : exits + copies all statistics to the clipboard

#### v24.8.8
![image](https://github.com/user-attachments/assets/28df2a1b-c60c-4742-8f01-b2d83c841af5)
* Explicit localhost IP identifier. 
* Human readable byte size statistics
* Simplified UI (localhost traffic is now implicitly all inbound, while the rest are implicitly all outbound)

#### v24.8.7 
![image](https://github.com/user-attachments/assets/1c8614bf-b622-48a7-a851-f18dca5e7d5c)

* First release
* [Credits](https://chatgpt.com/share/6011896c-cc29-4d53-8e83-360bc17835eb)
