# Install Procmon

## Ubuntu 18.04
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

#### 3. Install updated Linux kernel
Minimum Linux kernel version to run `Procmon` is 4.18 that is *not* shipped with Ubuntu 18.04 GA.
To use version 4.18 or newer you can:

1. Use Ubuntu HWE kernel (See [here]( https://wiki.ubuntu.com/Kernel/LTSEnablementStack) for reference) or

2. Use a tool like `ukuu`, for example:
    ```sh
    sudo apt-get install gdebi
    wget https://github.com/teejee2008/ukuu/releases/download/v18.9.1/ukuu-v18.9.1-amd64.deb
    sudo gdebi ukuu-v18.9.1-amd64.deb 
    sudo ukuu --install v4.18
    ```

