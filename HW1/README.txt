All the .py files in this folder are written in Python 3.9

Ensure the following libraries are installed before running:
- dnspython
- cryptography

For Part C only:
- numpy
- matplotlib

--------------------------------------------

For code execution, run below commands. If you are running in M1 Mac, ensure you are doing so in a conda environment. Do not run when connected to Wolfie-Secure Wifi. Use Wolfie-Guest instead, or connect to a VPN. Sometimes, you may get a None reference error, which may be because the connection to one of the DNS servers (mostly root) was refused. In such cases, try again, or connect to a different internet source or even VPN.


Part A)
python3 ./mydig.py netflix.com A
or
refer output of mydig_output.txt


Part B)
python3 ./mydig_dnssec.py verisigninc.com A
or
refer to implementation in 'DNSSEC Implementation.pdf'


Part C)
python3 ./part_c.py
or
refer to graphs of previous execution in "Part C Report.pdf"

---------------------------------------------