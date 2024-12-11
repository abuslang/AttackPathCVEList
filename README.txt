This script will list all CVEs for each resource with an active Attack Path Policy.

save all 3 files to a new folder for ease of use

config.py                       ->      set configuration variables
authenticate.py                 ->      authenticates and gets a JWT
get-ap-cve-by-resource.py       ->      python script to create the ouput     

1. open config.py
    - paste in your public key
    - paste in your private key
    - paste in your app url

2. run the script
    - if using the terminal
        - change directory to where the files are 
        - $ chmod +x get-ap-cve-by-resources.py
        - $ ./get-ap-cve-by-resources.py
    - or if you have any IDE could run there as well


1 thing to note is that you can change the filters for the intial search on line 54 in get-ap-cve-by-resource.py
change timeAmount to the number of months you want to include

initial_params = {
    'timeType': 'relative',
    'timeAmount': '12',             # change this value to change the time frame of search
    'timeUnit': 'month',
    'detailed': 'true',
    'policy.type': "attack_path"    # you can also add the field "policy.severity" and set it to "critical", "high", etc

}

contact: aquadri@paloaltonetworks.com
