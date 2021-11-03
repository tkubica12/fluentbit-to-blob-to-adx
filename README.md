# Fluent Bit to Azure Blob to Azure Data Explorer
Storing and analyzing critical events in Azure Sentinel as SIEM solution brings a lot of advantages, but might be costly for long term storage of low priority events that might not bring much value for real-time detection and response, but might be significant for forensics and post mortem.

This is simplistic PoC to explore option to configure server with Fluent Bit as syslog destination for low severity messages. Fluent Bit would then send data to be stored as append blob in cheap Azure Blob Storage (where potential tiering to archive can happen to lower cost even more). On top of this we will provision Azure Data Explorer to be able to filter and analyze data only when needed by either connecting specific space as external data (slow operation) or ingest data to ad-hoc ADX cluster (for high performing analytical operations).

# Prepare VM with Fluent Bit

```bash
az group create -n fluentbit -l westeurope
az network nsg create -n fluentbit -g fluentbit 
az network nsg rule create -n ssh -g fluentbit --nsg-name fluentbit --priority 120 --source-address-prefixes $(curl ifconfig.io) --destination-port-ranges 22 
az vm create -n fluentbit \
    -g fluentbit \
    --image Canonical:0001-com-ubuntu-server-focal:20_04-lts:latest \
    --size Standard_B1s \
    --admin-username tomas \
    --ssh-key-values ~/.ssh/id_rsa.pub \
    --nsg fluentbit \
    --public-ip-address fluentbit
```

# Prepare storage account

```bash
echo storageName=tomstorage$RANDOM > .env
source .env
az storage account create -n $storageName -g fluentbit --sku Standard_LRS
echo storageKey=$(az storage account keys list -n $storageName -g fluentbit --query [0].value -o tsv) >> .env
scp .env tomas@$(az network public-ip show -n fluentbit -g fluentbit --query ipAddress -o tsv):
```

# Connect to VM, install and configure Fluent Bit

```bash
ssh tomas@$(az network public-ip show -n fluentbit -g fluentbit --query ipAddress -o tsv)
source .env
wget -qO - https://packages.fluentbit.io/fluentbit.key | sudo apt-key add -
echo deb https://packages.fluentbit.io/ubuntu/focal focal main | sudo tee -a /etc/apt/sources.list
sudo apt-get update
sudo apt-get install td-agent-bit -y
cat << EOF > td-agent-bit.conf 
[SERVICE]
    flush     1
    log_level info
    Parsers_File parsers.conf

[INPUT]
    Name     syslog
    Parser   syslog-rfc5424
    Listen   0.0.0.0
    Port     514
    Mode     udp

[OUTPUT]
    name                  azure_blob
    match                 *
    account_name          $storageName
    shared_key            $storageKey
    path                  collector1
    container_name        logs
    auto_create_container on
    tls                   on
EOF
    
sudo mv ./td-agent-bit.conf /etc/td-agent-bit/
sudo service td-agent-bit restart
sudo service td-agent-bit status
```

# Generate some syslog messages

```bash
ssh tomas@$(az network public-ip show -n fluentbit -g fluentbit --query ipAddress -o tsv)
logger -n 127.0.0.1 srcIp=1.2.3.4 dstIp=5.4.3.2 dstPort=80 action=allow
logger -n 127.0.0.1 srcIp=1.2.3.4 dstIp=5.4.3.2 dstPort=8080 action=deny
logger -n 127.0.0.1 srcIp=2.2.3.4 dstIp=5.4.3.2 dstPort=443 action=allow
logger -n 127.0.0.1 srcIp=2.2.3.4 dstIp=5.4.3.2 dstPort=88 action=allow
logger -n 127.0.0.1 srcIp=3.2.3.4 dstIp=5.4.3.2 dstPort=80 action=allow
logger -n 127.0.0.1 srcIp=3.2.3.4 dstIp=5.4.3.2 dstPort=443 action=allow
logger -n 127.0.0.1 srcIp=1.2.3.4 dstIp=9.4.3.2 dstPort=3389 action=deny
logger -n 127.0.0.1 srcIp=1.2.3.4 dstIp=9.4.3.2 dstPort=443 action=allow
logger -n 127.0.0.1 srcIp=1.2.3.4 dstIp=9.4.3.2 dstPort=80 action=deny
```


# Create and configure Azure Data Explorer

```bash
az extension add -n kusto
az kusto cluster create -n tomasadx123 -g fluentbit --sku name="Dev(No SLA)_Standard_E2a_v4" capacity=1 tier="Basic" --public-network-access "Enabled"
az kusto database create --cluster-name tomasadx123 --database-name mydb -g fluentbit --read-write-database soft-delete-period=P365D hot-cache-period=P31D location=westeurope
```

# Connect file to ADX as external table
First option to parse and analyze data is to connect it to ADX as external table (low performance, but immediate availability).

Open ADX UI and select wizard to create external table.

[![](/images/2021/2021-11-03-14-13-30.png)](/images/2021/2021-11-03-14-13-30.png)

Select name.

[![](/images/2021/2021-11-03-18-48-59.png)](/images/2021/2021-11-03-18-48-59.png)

On storage account container generate SAS URL with Read a List permissions.

[![](/images/2021/2021-11-03-18-50-49.png)](/images/2021/2021-11-03-18-50-49.png)

Add as source in ADX.

[![](/images/2021/2021-11-03-18-51-23.png)](/images/2021/2021-11-03-18-51-23.png)

Select JSON as data format.

[![](/images/2021/2021-11-03-18-52-07.png)](/images/2021/2021-11-03-18-52-07.png)

We will do few modifications of schema. Delete @timestamp column, we have time in different one.

[![](/images/2021/2021-11-03-18-54-17.png)](/images/2021/2021-11-03-18-54-17.png)

Change data type of pri (priority) to number.

[![](/images/2021/2021-11-03-18-55-13.png)](/images/2021/2021-11-03-18-55-13.png)

Table is created.

[![](/images/2021/2021-11-03-18-55-49.png)](/images/2021/2021-11-03-18-55-49.png)

We can now retrieve data.

[![](/images/2021/2021-11-03-18-56-28.png)](/images/2021/2021-11-03-18-56-28.png)

Let's write little more complex query to parse syslog message and filter on result.

```
external_table("myexternaltable") 
| project srcIp = extract(@"srcIp=(.*?)\s", 1, message),
  dstIp = extract(@"dstIp=(.*?)\s", 1, message),
  dstPort = extract(@"dstPort=(.*?)\s", 1, message),
  action = extract(@"action=(.*?)$", 1, message)
| where action == "allow"
```

[![](/images/2021/2021-11-03-18-59-33.png)](/images/2021/2021-11-03-18-59-33.png)

# Ingest data from file to ADX
Another option is to ingest data into ADX so we can than run complex queries with high performance. Also you can configure ADX to to automate ingestion in batches over time.

[![](/images/2021/2021-11-03-19-01-33.png)](/images/2021/2021-11-03-19-01-33.png)

Select new table name.

[![](/images/2021/2021-11-03-19-02-11.png)](/images/2021/2021-11-03-19-02-11.png)

Make container your source.

[![](/images/2021/2021-11-03-19-03-44.png)](/images/2021/2021-11-03-19-03-44.png)

Repeat steps from previous example - parse as JSON, remove @timestamp column and change pri data type to decimal.

[![](/images/2021/2021-11-03-19-04-44.png)](/images/2021/2021-11-03-19-04-44.png)

Wait for ingestion.

[![](/images/2021/2021-11-03-19-05-21.png)](/images/2021/2021-11-03-19-05-21.png)

We can now query data.

```
['myingestedtable'] 
| project srcIp = extract(@"srcIp=(.*?)\s", 1, message),
  dstIp = extract(@"dstIp=(.*?)\s", 1, message),
  dstPort = extract(@"dstPort=(.*?)\s", 1, message),
  action = extract(@"action=(.*?)$", 1, message)
| where action == "allow"
```

[![](/images/2021/2021-11-03-19-06-24.png)](/images/2021/2021-11-03-19-06-24.png)

# Next steps
This is just very basic PoC. More investigation is needed to figure out file rotation to folders based on time etc.







