# PMD TXQ calculation
The python file calculate hash index for PMD TXQ used in 17.7 and later release. The --old_crc will generate hash index based on 17.7 and 17.8 release with modulo 8 to match the supported PMD TXQ. Release 17.9 and later use modulo 12 without the --old_crc option matching the supported PMD TXQ.

Refer to Cisco documentation for more details: https://www.cisco.com/c/en/us/support/docs/routers/sd-wan/224128-improve-throughput-on-catalyst-8000v.html

The user can specify the protocol parameter as "gre" or "tcp" or "udp" or any decimal The ip_test.txt contain the following column dst, src, prot, dstport, srcport separate by a single space.

How to create virtual environment:

*  Upgrade to python 3.8.9 or higher
    - Check python version
        - python3 --version
*  Install pip if not yet installed
    - curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    - python3 get-pip.py
*  Create virtual environment
    - python3 -m venv c8kv-hash
    - cd c8kv-hash
    - source bin/activate
    - git clone https://www-github.cisco.com/hntran/c8kv-aws-pmd-hash.git
    - cd c8kv-aws-pmd-hash
    - python3 -m pip install --upgrade pip
    - pip install -r requirements.txt
    - Run script for 17.7 and 17.8 release
        - python3 c8kv_multitxq_hash.py --old_crc 1 --dest_network 192.168.1.0/24 --src_network 192.168.2.0/24
        - python3 c8kv_multitxq_hash.py --old_crc 1 --ip_file test.txt
    - Run script for 17.9 and later release
        - python3 c8kv_multitxq_hash.py --dest_network 192.168.1.0/24 --src_network 192.168.2.0/24 --prot gre
        - python3 c8kv_multitxq_hash.py --dest_network 192.168.1.0/24 --src_network 192.168.2.0/24 --prot udp --src_port 12346 --dst_port 12346 --unique_hash 1
        - python3 c8kv_multitxq_hash.py --ip_file test.txt

*  Get out of virtual environment
    - deactivate
    
