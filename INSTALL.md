# Install Procmon

## Ubuntu 20.04, 22.04, 24.04
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

## Debian 11
#### 1. Register Microsoft key and feed
```sh
wget -q https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
```

#### 2. Install Procmon
```sh
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install procmon
```

## Debian 12
#### 1. Register Microsoft key and feed
```sh
wget -q https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
```

#### 2. Install Procmon
```sh
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install procmon
```

## Fedora 38
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/fedora/38/packages-microsoft-prod.rpm
```

#### 2. Install Procmon
```sh
sudo dnf install procmon
```

## Fedora 39
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/fedora/39/packages-microsoft-prod.rpm
```

#### 2. Install Procmon
```sh
sudo dnf install procmon
```

## Fedora 40
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/fedora/40/packages-microsoft-prod.rpm
```

#### 2. Install Procmon
```sh
sudo dnf install procmon
```

## RHEL 7
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/rhel/7/packages-microsoft-prod.rpm
```

#### 2. Install Procmon
```sh
sudo yum install procmon
```

## RHEL 8
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/rhel/8/packages-microsoft-prod.rpm
```

#### 2. Install Procmon
```sh
sudo yum install procmon
```

## RHEL 9
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/rhel/9/packages-microsoft-prod.rpm
```

#### 2. Install Procmon
```sh
sudo yum install procmon
```

## CentOS 7
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/centos/7/packages-microsoft-prod.rpm
```

#### 2. Install Procmon
```sh
sudo yum install procmon
```

## openSUSE 15
#### 1. Register Microsoft key and feed
```sh
sudo zypper install libicu
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
wget -q https://packages.microsoft.com/config/opensuse/15/prod.repo
sudo mv prod.repo /etc/zypp/repos.d/microsoft-prod.repo
sudo chown root:root /etc/zypp/repos.d/microsoft-prod.repo
```

#### 2. Install Procmon
```sh
sudo zypper install procmon
```

## SLES 12
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/sles/12/packages-microsoft-prod.rpm
```

#### 2. Install Procmon
```sh
sudo zypper install procmon
```

## SLES 15
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/sles/15/packages-microsoft-prod.rpm
```

#### 2. Install Procmon
```sh
sudo zypper install procmon
```