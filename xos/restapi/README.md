You can follow below commands:

# Pre-procedure
Execute the following command to generate service information of XOS Core.
```
docker exec swarmservice_xos_ui_1 python tosca/run.py xosadmin@opencord.org /opt/cord_profile/swarm-node.yaml; pushd /opt/cord/build/platform-install; ansible-playbook -i inventory/swarm-service onboard-fwaas-playbook.yml; popd
```

# Procedure
```
>> usage
./add_rule.sh
./add_firewall.sh {rule_id}

>> example
./add_rule.sh 
./add_firewall.sh "f71dc5e1-0bb8-4816-ab00-4162c32b721b,549e654c-d7d6-4f52-b30c-2b0e09f99730"
```
