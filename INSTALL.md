# Install Procmon

## Ubuntu 18.04 & 20.04
#### 1. Register Microsoft key and feed
```sh
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
```

#### 2. Install Procmon
```sh
sudo apt-get update
sudo apt-get install procmon
```

