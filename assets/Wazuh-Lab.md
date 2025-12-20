# Wazuh - Endpoint Security

> By:
>
> - Galiev Arsen - a.galiev@innopolis.university
> - Nguen Ilya-Linh - i.nguen@innopolis.university
> - Zavadskii Peter - p.zavadskii@innopolis.university

Reference to Innopolis University F25 Network and Cybersecurity course: [link](https://github.com/FIS-NCS/NCS-F25)

# Exercise 1: Vulnerability Detection and SCA

- What is the difference between authenticated and unauthenticated vulnerability scans? Why do both types need to be performed periodically?

An **unauthenticated** scan is performed as an _external attacker_, while an **authenticated** scan is an authorized process that analyzes internal resources (not available to external users).

- Show detected vulnerabilities on the monitored endpoint. Explain whether the results indicate that Wazuh performed an authenticated or an unauthenticated scan.

![image copy 3.png](https://raw.githubusercontent.com/bucketio/img10/main/2025/11/28/1764343469069-a9c87acb-ec16-47bc-ad42-c1e2579f3e14.png "image copy 3.png")
![image copy 4.png](https://raw.githubusercontent.com/bucketio/img12/main/2025/11/28/1764343468040-ed53feb8-73e6-4903-8749-d0e3753ab708.png "image copy 4.png")

Wazuh obviously performed an authenticated scan. Two facts can be provided:

1. The scan was done by the agent _we installed_ on the endpoint, so it has full access to the system.
2. The scan contains results for system packages (e.g., Debian toolkit utilities).

- What is SCA? Show and explain the relevant scans carried out by Wazuh's SCA module against the monitored endpoint.

SCA (Software Composition Analysis) is an automated process where software is checked for Open Source Software (OSS), which is further checked for updates, vulnerabilities, license problems, and policy creation.

Reference: [Solar blog](https://rt-solar.ru/products/solar_appscreener/blog/3597/)

I chose an SCA scan for the openssh-server (sshd) that I had previously installed on the agent:

![image copy 12.png](https://raw.githubusercontent.com/bucketio/img14/main/2025/11/28/1764343457876-fd78d32c-1c73-4fa6-9dda-3500d02362a2.png "image copy 12.png")

Yes, there are different agent names in the screenshots because I am still struggling with Active Response and added another screenshot.

# Exercise 2: File Integrity Monitoring

Configure Wazuh's File Integrity Monitoring (FIM) to audit a directory of your choice.

How I did it... (two attempts with two different folders)

- https://asciinema.org/a/2NqmTUFVYLzuL3YtXH9c4hD8x
- https://asciinema.org/a/X8QlU6s76aemuJrYL21jBvYOB

---

Create a text file in the monitored directory then wait for 5 seconds.
Add content to the text file and save it. Wait for 5 seconds.
Delete the text file from the monitored directory.
Show relevant events (triggered rules) in the dashboard.

Since in one of the solutions I specified the `/home` folder, the changes made during the `asciinema` recording affected the events:

![image copy 5.png](https://raw.githubusercontent.com/bucketio/img16/main/2025/11/28/1764343466856-d05ba7c4-1e5b-44fc-9f08-2b78584a192f.png "image copy 5.png")

![image copy 6.png](https://raw.githubusercontent.com/bucketio/img7/main/2025/11/28/1764343463197-a7485265-286a-4ec4-95f6-a427298cbbcd.png "image copy 6.png")

Here is another attempt, as required by the task:

![image copy 9.png](https://raw.githubusercontent.com/bucketio/img16/main/2025/11/28/1764343462015-c1478e13-dd82-479e-bbd9-4122b0c6a472.png "image copy 9.png")

# Exercise 3: Active Response

There are several obstacles here:

1. The agent by default does not have SSH server logging and logger.
2. The Wazuh manager container has a minimal security setup, with almost no way to change the config at the moment and restart.
3. The Wazuh manager lacks rulesets for DDoS, SSH, PAM, and syslog.

Below are some screenshots of my attempts before I found the manager config in the lab folders. Now I will redeploy everything.

Here, Wazuh alerts that busybox-syslog is a trojan.

![image copy 11.png](https://raw.githubusercontent.com/bucketio/img2/main/2025/11/28/1764343459238-965dbcba-1413-41ef-b261-b07adb44b76f.png "image copy 11.png")

Here I got SSH logs.

![image copy 10.png](https://raw.githubusercontent.com/bucketio/img17/main/2025/11/28/1764343460715-7926f4e1-a35a-49e2-b4e4-c7f1caa3833d.png "image copy 10.png")

A brief overview of my attempts: https://asciinema.org/a/iy68DxlqF74J8yMZkt5IoHdjn

The issue was that I used `busybox-syslogd` instead of `rsyslog`...

So what I have done to make it work:

1. (useless step) Changed `wazuh_manager.conf` from the repository:

```xml
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5763</rules_id>
    <timeout>600</timeout>
  </active-response>
```

A rule for IP blocking.

Then I restarted the container from the network. It didn't work since I had not configured `ossec.conf` correctly on the endpoint agent, and the logging system was not suitable for Wazuh analyzer.

2. Configuring `ossec.conf` on the endpoint:

```xml
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
```

This part is responsible for scanning the logs for authentication. The `sshd` writes logs about logins/logouts here.

```xml
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5763</rules_id>
    <timeout>600</timeout>
  </active-response>
```

Duplicating the blocking rule.

```xml
 <command>
   <name>firewall-drop</name>
   <executable>firewall-drop</executable>
   <timeout_allowed>yes</timeout_allowed>
 </command>
```

Creating the command for IP block by endpoint firewall.

3. Removing `busybox-syslogd` and installing `rsyslog`. Now Wazuh correlates logs correctly.

Let's check the rule for the threat:

1. Hydra attacking.

```bash
sudo hydra -t 4 -l dev -P ~/Downloads/rockyou.txt 172.18.0.2 ssh
```

![image copy 14.png](https://raw.githubusercontent.com/bucketio/img1/main/2025/11/28/1764343456599-008196f0-4c0f-4ad1-9fcc-98e3de3025fd.png "image copy 14.png")

2. Wazuh logs

![image copy 16.png](https://raw.githubusercontent.com/bucketio/img16/main/2025/11/28/1764343451586-fe1533da-aec5-4704-8272-4f435f3f0bba.png "image copy 16.png")

We can see that the manager detected brute-forcing and blocked our IP.

![image copy 17.png](https://raw.githubusercontent.com/bucketio/img11/main/2025/11/28/1764343447840-9697c579-8df1-4fd9-bdda-e712bec27167.png "image copy 17.png")

3. Checking the block

![image copy 15.png](https://raw.githubusercontent.com/bucketio/img19/main/2025/11/28/1764343455337-90cc88d4-8929-4a94-a323-acde609c4ed2.png "image copy 15.png")

The protected agent is now unreachable.
