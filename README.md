
# 🎯 Threat Intelligence - Phishing Email Investigation 

This write-up outlines an investigation of three phishing emails using `.eml` files. We uncover the attacker’s social engineering tactics, trace sender metadata, identify malicious payloads, and extract IOCs.
<img width="667" height="167" alt="phishing 0 emails 1 2 3 to use" src="https://github.com/user-attachments/assets/4f151829-9388-4782-8906-54331cf91a19" />

We answer each question by showing **how** the data was found, and reference each image where it belongs.

---

## 🧪 Email 1 Investigation – Spoofed LinkedIn Notification

This is the first phishing email, pretending to be a LinkedIn alert.

We opened `Email1.eml` using Thunderbird.

<img width="199" height="169" alt="email 1" src="https://github.com/user-attachments/assets/db43b529-817c-4bf0-8d44-7fea2e6f5e00" />

---

### 📬 How to Open the Email Securely

We right-click the `.eml` file and chose to open it with Thunderbird Mail.

<img width="371" height="214" alt="phishing 2" src="https://github.com/user-attachments/assets/4016ee72-29f8-4151-8e59-afc89c4c31a8" />

This allows us to analyze the email body and headers safely without triggering remote content.

---

### 📩 What did the email say?

Here’s the full message pretending to be from LinkedIn.


It says: <img width="1213" height="755" alt="phishing 3" src="https://github.com/user-attachments/assets/5ff019cf-1b7c-420e-9eef-fe0ba051256d" />


**“You have 5 new message(s)”**
This is designed to trick the user into clicking a button that likely leads to a malicious site.

---

### 📌 Full Headers View

To analyze the technical metadata, we enable full headers in Thunderbird:
`View > Headers > All`

<img width="448" height="308" alt="phishing 4" src="https://github.com/user-attachments/assets/9afcd090-65f4-485d-963a-14e100e65706" />

---

### 📡 How to Find the Sender’s IP

In the header we found this:

```
Received: from sc500.whpservers.com (204.93.183.11)
```

<img width="1223" height="211" alt="phishing 5" src="https://github.com/user-attachments/assets/3c4ef785-8e58-4356-896b-1fb7b8a6e6b0" />

The originating IP is: `204.93.183.11`

It went through **4 hops**, which we counted from each `Received:` line.

---

## 🌐 IP & Domain Attribution for `204.93.183.11`

We performed WHOIS and reputation lookups to investigate the sender’s IP.

---

### 📄 WHOIS Results

WHOIS revealed the net name, owner, and customer info:

<img width="450" height="248" alt="phishing 9 Whois" src="https://github.com/user-attachments/assets/8787fff6-3fd5-4266-afa7-7610318098c4" />

* **NetName:** SCNET-204-93-183-0-24
* **Customer:** Complete Web Reviews

---

### 🌍 IP Reputation Results

Using an IP reputation site, we saw:

<img width="1575" height="903" alt="phishing 8" src="https://github.com/user-attachments/assets/d3380957-1fae-4c55-8b6b-18a14482c10c" />

* **Domain:** scnet.net
* **Hostname:** sc500.whpservers.com
* **Reputation:** Neutral but hosted in Chicago with suspicious traits


---

## 📦 Malicious File Analysis – Attachments Found in Emails

We extracted two suspicious files from the phishing emails:

1. A `.zip` file named `Proforma Invoice P101092292891 TT slip pdf.rar.zip`
2. A hidden `.xls` file named `Sales_Receipt 5606.xls`

---

### 🔐 Hashing File #1 – Suspicious ZIP Archive

We calculated the hash using GtkHash:

<img width="552" height="326" alt="phishing 10a" src="https://github.com/user-attachments/assets/614124a3-75b2-43be-a81f-7a80766ab981" />

* **MD5:** `4132a73c448cd2b5813dc2d34868aba9`
* **SHA256:** `c058e8c11863d5dd1f05e0c7a86e232c93d0e979fdb28`

---

### 🧪 VirusTotal Results – ZIP Archive

<img width="1331" height="1221" alt="phishing 11" src="https://github.com/user-attachments/assets/35d8bd80-a1f7-4794-9711-f768072b37b3" />

* 55 out of 67 vendors flagged it as **malicious**
* Detected as **Trojan.noon / farevib**
* Identified as a **dropper with runtime modules**

---

### 📎 File #2 – Malicious XLS in the Email

We found a reference to the XLS file in the raw email content:

<img width="630" height="90" alt="phishing 12 email 3 starts " src="https://github.com/user-attachments/assets/b7cafdcc-46ac-4ca2-aa62-0fdbc6416883" />

The email disguised it as `Sales_Receipt 5606.xls`.

---

### 🔐 Hashing the XLS File

<img width="778" height="688" alt="phishing 13 email 3 starts" src="https://github.com/user-attachments/assets/f1f7851f-ba51-4b8f-a842-0504c1f85984" />

* **MD5:** `e63deaea517fc2064ff808e11e1ad55`
* **SHA256:** `b8ef959a9176aef07fdca8705254a163b50b49a17217a4ff010748f759d4a35d`

---

### 🧪 VirusTotal Results – XLS File

<img width="1329" height="839" alt="phishing 14 email 3  dridex" src="https://github.com/user-attachments/assets/65b01d2a-d104-4328-b5a2-511682395362" />

* 39/62 vendors flagged it as **malicious**
* VBA macros detected
* Activity consistent with **Dridex / x97m / valyria** malware families
* Uses **string manipulation, WMI**, and **macro obfuscation**

---

## 🧾 Final IOC Summary

| Type               | Value                                                              |
| ------------------ | ------------------------------------------------------------------ |
| Social Engineering | Spoofed LinkedIn Email                                             |
| Sender Email       | `darkabutla@sc500.whpservers.com`                                  |
| Recipient Email    | `cabbagecare@hotmail.com`                                          |
| Originating IP     | `204[.]93[.]183[.]11`                                              |
| IP Domain          | `scnet.net`                                                        |
| IP Owner           | `Complete Web Reviews`                                             |
| Malicious ZIP Name | `Proforma Invoice P101092292891 TT slip pdf.rar.zip`               |
| ZIP SHA256         | `c058e8c11863d5dd1f05e0c7a86e232c93d0e979fdb28`                    |
| XLS File Name      | `Sales_Receipt 5606.xls`                                           |
| XLS SHA256         | `b8ef959a9176aef07fdca8705254a163b50b49a17217a4ff010748f759d4a35d` |
| Malware Families   | `noon`, `farevib`, `x97m`, `Dridex`                                |
