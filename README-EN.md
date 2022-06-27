## IT Army of Ukraine Official Tool

### Use flag `--lang en` to enable English translation

- Built-in proxy server database with a wide range of IPs around the world
- Possibility to set a huge number of targets with automatic load balancing
- A variety of different load-testing methods
- Effective utilization of your resources due to the asynchronous architecture

### ⏱ Recent updates

- **27.06.2022** Added Spanish localization - use flag `--lang es`
- **22.06.2022** Performance improvements. The `--debug` option is deprecated to avoid negative impact on performance
- **10.06.2022** Introduced `--proxy` option for providing custom proxies directly from command args
- **08.06.2022** Added `--copies auto` option to set the value automatically based on the resources available

### 1. 💽 Installation options

#### A) Windows installer https://itarmy.com.ua/instruction/#mhddos/#windows

#### B) Python (if it doesn't work, try `python` or `python3.10` instead of `python3`)

Requires [Python](https://www.python.org/downloads/) and [Git](https://git-scm.com/download/)

    git clone https://github.com/porthole-ascend-cinnamon/mhddos_proxy.git
    cd mhddos_proxy
    python3 -m pip install -r requirements.txt

#### C) Docker

Install and start Docker: https://docs.docker.com/desktop/#download-and-install

### 2. 🕹 Running

#### Python with automatic updates (if it doesn't work, try `python` or `python3.10` instead of `python3`)

    ./runner.sh python3 --itarmy

For [**Termux for Android**](https://telegra.ph/mhddos-proxy-for-Android-with-Termux-03-31) use:

    TERMUX=1 bash runner.sh python --itarmy -t 1000

#### Python (manual updates required) (if it doesn't work, try `python` or `python3.10` instead of `python3`)

    python3 runner.py --itarmy

#### Docker (for Linux, add sudo in front of the command)

    docker run -it --rm --pull always ghcr.io/porthole-ascend-cinnamon/mhddos_proxy --itarmy

### 3. 🛠 Configuration and options

All options can be combined and specified in any order

- Consider adding your IP/VPN to the attack (especially when running on dedicated server), add flag `--vpn`
- To use targets provided by IT Army of Ukraine (https://itarmy.com.ua/), add the `--itarmy` flag  
- Number of threads: `-t XXXX` - the default is 8000 (or 4000 if the machine has only one CPU).
- Number of copies: `--copies X` or `--copies auto` - in case you have 4+ CPU and stable network 100+ Mb/s

```
usage: runner.py [-t THREADS] [--copies COPIES] [--itarmy] [--lang {ua,en}] [--vpn]
                 [-c URL|path] [--proxies URL|path] [--proxy [PROXY ...]]
                 [--http-methods METHOD [METHOD ...]] [targets...]

  -h, --help             show all available options
  -t, --threads 8000     Number of threads (default is 8000 if CPU > 1, 4000 otherwise)
  --copies 1             Number of copies to run (default is 1). Use "auto" to set the value automatically
  --itarmy               Use targets from https://itarmy.com.ua/  
  --lang {ua,en,es}      Select language (default is ua)
  --vpn                  Use both my IP and proxies. Optionally, specify a chance of using my IP (default is 2%)
  -c, --config URL|path  URL or local path to file with targets list
  --proxies URL|path     URL or local path(ex. proxies.txt) to file with proxies to use
  --proxy [PROXY ...]    List of proxies to use, separated by spaces
  --http-methods GET     List of HTTP(L7) methods to use (default is GET).

positional arguments:
   targets               List of targets, separated by space
```

### 5. 🐳 Community (mostly in Ukrainian)
- [Detailed (unofficial) installation instructions](docs/installation.md)
- [Create a botnet of 30+ free and standalone Linux servers](https://auto-ddos.notion.site/dd91326ed30140208383ffedd0f13e5c)
- [Scripts with automatic install](https://t.me/ddos_separ/1126)
- [Analysis of mhddos_proxy](https://telegra.ph/Anal%D1%96z-zasobu-mhddos-proxy-04-01)
- [Example of running via docker on OpenWRT](https://youtu.be/MlL6fuDcWlI)
- [VPN](https://auto-ddos.notion.site/VPN-5e45e0aadccc449e83fea45d56385b54)
- [Setup with Telegram notifications](https://github.com/sadviq99/mhddos_proxy-setup)

### 6. Custom proxies

#### Command line

To specify custom proxy use `--proxy` option:

    python3 runner.py --proxy socks4://114.231.123.38:3065

Multiple proxies are allowed (space separated):

    python3 runner.py --proxy socks4://114.231.123.38:3065 socks5://114.231.123.38:1080

If the list of custom proxies gets too long, consider switching to file-based configuration (see the next section).

#### File format (any of the following):

    IP:PORT
    IP:PORT:username:password
    username:password@IP:PORT
    protocol://IP:PORT
    protocol://IP:PORT:username:password

where `protocol` can be one of 3 options: `http`|`socks4`|`socks5`. 
If `protocol` is not specified, default value `http` is used.
For example, for a public `socks4` proxy the format will be fhe following:

    socks4://114.231.123.38:3065

and for the private `socks4` proxy format can be one of the following:

    socks4://114.231.123.38:3065:username:password
    socks4://username:password@114.231.123.38:3065

**URL of the remote file for Python and Docker**

    --proxies https://pastebin.com/raw/UkFWzLOt

where https://pastebin.com/raw/UkFWzLOt is your web page with a list of proxies (each proxy should be on a new line)  

**Path for the local file for Python**  
  
Put the file in the folder with `runner.py` and add the following option to the command (replace `proxies.txt` with the name of your file)

    --proxies proxies.txt

where `proxies.txt` is your proxy list file (each proxy should be on a new line)
