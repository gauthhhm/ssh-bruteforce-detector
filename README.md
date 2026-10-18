\# SSH Brute-Force Detector



A Python command-line tool that scans Linux `auth.log` files and flags IP addresses showing SSH brute-force or password-spraying behavior, with findings mapped to MITRE ATT\&CK.



\## Features



\- Parses failed SSH logins, including `invalid user` entries

\- Time-window detection: flags an IP only when enough failures happen within a set number of minutes

\- Distinguishes brute force (one account) from password spraying (many accounts)

\- Maps findings to MITRE ATT\&CK techniques T1110.001 and T1110.003

\- Ranked terminal report plus a JSON export

\- No third-party dependencies



\## Installation



Requires Python 3.8 or newer.



```

git clone https://github.com/gauthhhm/ssh-bruteforce-detector.git

cd ssh-bruteforce-detector

```



\## Usage



```

python detector.py samples/auth.log

python detector.py samples/auth.log -t 5 -w 10

python detector.py --help

```



| Option | Default | Meaning |

|---|---|---|

| `logfile` | `samples/auth.log` | Path to the log file |

| `-t`, `--threshold` | 3 | Failures inside the window needed to flag an IP |

| `-w`, `--window` | 10 | Time window in minutes |

| `-s`, `--spray` | 3 | Unique usernames from one IP to classify as spraying |

| `-o`, `--output` | `report.json` | JSON report path |

| `-y`, `--year` | current year | Year of the log (auth.log timestamps have none) |



\## Sample output



!\[screenshot](screenshot.png)



```

IP                Attempts  In window  Users  Type               Last seen

198.51.100.23     8         8          1      Brute Force        2026-10-18 10:31:47

203.0.113.5       4         4          3      Password Spraying  2026-10-18 10:15:10

```



The sample log in `samples/` also contains cases the tool correctly ignores: a slow attacker (`192.0.2.99`) with 6 failures spread over 100 minutes, and a legitimate user (`192.0.2.10`) who mistyped a password twice before logging in.



\## How detection works



1\. Every `Failed password` line is parsed for timestamp, username, and source IP.

2\. Failures are grouped by IP.

3\. For each IP, a sliding window finds the most failures within any single window (default 10 minutes).

4\. If that peak meets the threshold (default 3), the IP is flagged.

5\. If the flagged IP tried 3 or more unique usernames, it is classified as password spraying. Otherwise, brute force.



\## MITRE ATT\&CK mapping



| Behavior | Technique |

|---|---|

| Repeated guesses against one account | T1110.001 Password Guessing |

| One source trying many accounts | T1110.003 Password Spraying |



\## Limitations



\- Detects `Failed password` lines only. Other failure formats (for example `Connection closed ... \[preauth]`) are not yet counted.

\- IPv4 only.

\- Assumes all entries fall within one calendar year.

\- Analyzes a file after the fact. It is not a real-time monitor.

\- Sample data is synthetic. Do not commit real logs containing real IPs or usernames.



\## License



MIT

