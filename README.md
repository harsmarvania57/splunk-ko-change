# splunk-ko-change
Bulk modify Splunk Knowledge Object's owners, permissions, apps, sharing and move them to another app. To change permission, owner or move knowledge object with script given in this repository you require Splunk Admin privilege.

Python script which is provided in this repo works fine on stand alone search head and Search Head Cluster(SHC). When you have Search Head Cluster(SHC) you need to run this script on one of the search head member(Not on all).

### Type of Knowledge Objects and what you can change with this script

<table>
  <thead>
    <tr>
      <th>Knowledge Object</th>
      <th>Existing Sharing Permission</th>
      <th>Change Owner</th>
      <th>Move App</th>
      <th>Change Read Permission</th>
      <th>Change Write Permission</th>
      <th>Change Sharing Permission</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan=3>- Macro</br>- Savedsearch</br>- Dashboard</br>- Lookup File</br>- Lookup Definition</br>- Panel</br>- Field Transformation</br>- Workflow Action</br>- Tag*</br>- Field Extraction*</td>
      <td>Private</td>
      <td>:white_check_mark:</td>
      <td>:white_check_mark:</td>
      <td>:x:</td>
      <td>:x:</td>
      <td>:white_check_mark:</td>
    </tr>
    <tr>
      <td>App</td>
      <td>:white_check_mark:</td>
      <td>:white_check_mark:</td>
      <td>:white_check_mark:</td>
      <td>:white_check_mark:</td>
      <td>:white_check_mark:</td>
    </tr>
    <tr>
      <td>Global</td>
      <td>:white_check_mark:</td>
      <td>:white_check_mark:</td>
      <td>:white_check_mark:</td>
      <td>:white_check_mark:</td>
      <td>:white_check_mark:</td>
    </tr>
    <tr>
      <td colspan=7>* For Tag & Field extraction private (user) sharing from one user to another user & moving it to another app will not work on some of the older versions of Splunk</td>
    </tr>
  </tbody>
</table>

**NOTE: When you change sharing permission from `user` to `app` or `global` and if you do not provide `--readperm` and `--writeperm` parameter while changing permission then by default it will inherit App read and write permission respectively.**
**NOTE: When you use `filter` without parameter it will match that filter value with any parameter like title, search query, dashboard xml etc.**

### How to use script (Examples)
#### To check which knowledge objects you can move using `ko_change.py` script and for available script parameter you can use help as given below

```
[splunk@splunkserver01 etc]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py -h
usage: ko_change.py [-h] {list,change,move} ...

List/Transfer ownership/permission of splunk knowledge objects.

positional arguments:
  {list,change,move}  Command Choices
    list              List splunk knowledge objects
    change            Change ownership, read & write permission and sharing of
                      splunk knowledge objects
    move              Move knowledge objects to another app

optional arguments:
  -h, --help          show this help message and exit

[splunk@splunkserver01 etc]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py list -h
usage: ko_change.py list [-h]
                         {macro,savedsearch,dashboard,lookupdef,lookupfile,tag,field_extraction,panel,field_transformation,workflow_action}
                         ...

positional arguments:
  {macro,savedsearch,dashboard,lookupdef,lookupfile,tag,field_extraction,panel,field_transformation,workflow_action}
                        Knowledge Object Choices
    macro               To list macro
    savedsearch         To list savedsearch
    dashboard           To list dashboard
    lookupdef           To list lookupdef
    lookupfile          To list lookupfile
    tag                 To list tag
    field_extraction    To list field_extraction
    panel               To list panel
    field_transformation
                        To list field_transformation
    workflow_action     To list workflow_action

optional arguments:
  -h, --help            show this help message and exit

[splunk@splunkserver01 etc]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py change savedsearch -h
usage: ko_change.py change savedsearch [-h] (--olduser OLDUSER | --file FILE)
                                       [--filter FILTER] [--host HOST]
                                       [--count COUNT] [--newuser NEWUSER]
                                       [--sharing SHARING]
                                       [--readperm READPERM]
                                       [--writeperm WRITEPERM]

optional arguments:
  -h, --help            show this help message and exit
  --olduser OLDUSER     Old Username
  --file FILE           Filename containing KO Title
  --filter FILTER       Filter by name
  --host HOST           Specify splunk server to connect to (defaults to local
                        server)
  --count COUNT         Number of KO to pull in single request (default 30)
  --newuser NEWUSER     New Username
  --sharing SHARING     New Sharing Permission
  --readperm READPERM   New Read Permission of KO
  --writeperm WRITEPERM
                        New Write Permission of KO
[splunk@splunkserver01 etc]$
```

#### To view knowledge object owned by user
In below example we will list savedsearch owned by "bob" user in all splunk apps.

```
[splunk@splunkserver01 ~]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py list savedsearch --user bob
Authentication method:
1.) Username and Password
2.) Auth token
Please select authentication method (Enter 1 or 2): 1
Enter username with admin privileges: admin
Enter password:
Fetched 4 out of total 4 knowledge objects.

--------------------------------
Total 4 savedsearch found
--------------------------------

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   
search        bob           Test_Savedsearch1   savedsearch   user          None          None          False         
search        bob           Test_Savedsearch2   savedsearch   user          None          None          False         
search        bob           Test_Savedsearch3   savedsearch   app           *             admin         False         
search        bob           Test_Savedsearch4   savedsearch   global        admin         admin         False         

[splunk@splunkserver01 ~]$
```

#### To view selected knowledge object owned by any user
In below example we will list selected savedsearches owned by any user from all splunk apps. I have created `savedsearch.txt` file and mentioned `Test_Savedsearch2` and `Test_Savedsearch3` as given below.

```
[splunk@splunkserver01 ~]$ cat /home/splunk/savedsearch.txt
Test_Savedsearch2
Test_Savedsearch3
[splunk@splunkserver01 ~]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py list savedsearch --file /home/splunk/savedsearch.txt
Authentication method:
1.) Username and Password
2.) Auth token
Please select authentication method (Enter 1 or 2): 1
Enter username with admin privileges: admin
Enter password:
Fetched 30 out of total 85 knowledge objects.
Fetched 60 out of total 85 knowledge objects.
Fetched 85 out of total 85 knowledge objects.

--------------------------------
Total 2 savedsearch found
--------------------------------

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   
search        bob           Test_Savedsearch2   savedsearch   user          None          None          False         
search        kevin         Test_Savedsearch3   savedsearch   app           *             admin         False         

[splunk@splunkserver01 ~]$
```

#### To change owner of knowledge object owned by user
In below example we will change savedsearches owned by user "bob" user to "kevin" user in all splunk apps.

```
[splunk@splunkserver01 ~]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py change savedsearch --olduser bob --newuser kevin
Authentication method:
1.) Username and Password
2.) Auth token
Please select authentication method (Enter 1 or 2): 1
Enter username with admin privileges: admin
Enter password:
Fetched 4 out of total 4 knowledge objects.

--------------------------------
Total 4 savedsearch found
--------------------------------

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   
search        bob           Test_Savedsearch1   savedsearch   user          None          None          False         
search        bob           Test_Savedsearch2   savedsearch   user          None          None          False         
search        bob           Test_Savedsearch3   savedsearch   app           *             admin         False         
search        bob           Test_Savedsearch4   savedsearch   global        admin         admin         False         

Do you want to change now?[y/n] y

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        Status    
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   ========  
search        bob           Test_Savedsearch1   savedsearch   user          None          None          False         Changed   
search        bob           Test_Savedsearch2   savedsearch   user          None          None          False         Changed   
search        bob           Test_Savedsearch3   savedsearch   app           *             admin         False         Changed   
search        bob           Test_Savedsearch4   savedsearch   global        admin         admin         False         Changed  
[splunk@splunkserver01 ~]$
```

#### To change owner of knowledge object owned by user and filter
In below example we will change savedsearche owned by user "bob" user to "kevin" user in all splunk apps with filter "Test_Savedsearch1".

```
[splunk@splunkserver01 ~]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py change savedsearch --olduser bob --newuser kevin --filter Test_Savedsearch1
Authentication method:
1.) Username and Password
2.) Auth token
Please select authentication method (Enter 1 or 2): 1
Enter username with admin privileges: admin
Enter password:
Fetched 1 out of total 1 knowledge objects.

--------------------------------
Total 1 savedsearch found
--------------------------------

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   
search        bob           Test_Savedsearch1   savedsearch   user          None          None          False                 

Do you want to change now?[y/n] y

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        Status    
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   ========  
search        bob           Test_Savedsearch1   savedsearch   user          None          None          False         Changed   
[splunk@splunkserver01 ~]$


[splunk@splunkserver01 ~]$ cat /home/splunk/savedsearch.txt
Test_Savedsearch2
Test_Savedsearch3
[splunk@splunkserver01 ~]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py change savedsearch --file /home/splunk/savedsearch.txt --filter "eai:acl.owner=bob" --filter "eai:acl.app=search" --newuser kevin
Authentication method:
1.) Username and Password
2.) Auth token
Please select authentication method (Enter 1 or 2): 1
Enter username with admin privileges: admin
Enter password:
Fetched 4 out of total 4 knowledge objects.

--------------------------------
Total 2 savedsearch found
--------------------------------

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   
search        bob           Test_Savedsearch2   savedsearch   user          None          None          False         
search        bob           Test_Savedsearch3   savedsearch   app           *             admin         False

Do you want to change now?[y/n] y

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        Status    
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   ========  
search        bob           Test_Savedsearch2   savedsearch   user          None          None          False         Changed
search        bob           Test_Savedsearch3   savedsearch   app           *             admin         False         Changed          
```

#### To change owner of selected knowledge object owned by any user
In below example we will change selected savedsearches owned by any user to "bob" user in all splunk apps. I have created `savedsearch.txt` file and mentioned `Test_Savedsearch2` and `Test_Savedsearch3` as given below.

```
[splunk@splunkserver01 ~]$ cat /home/splunk/savedsearch.txt
Test_Savedsearch2
Test_Savedsearch3
[splunk@splunkserver01 ~]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py change savedsearch --file /home/splunk/savedsearch.txt --newuser bob
Authentication method:
1.) Username and Password
2.) Auth token
Please select authentication method (Enter 1 or 2): 1
Enter username with admin privileges: admin
Enter password:
Fetched 30 out of total 85 knowledge objects.
Fetched 60 out of total 85 knowledge objects.
Fetched 85 out of total 85 knowledge objects.

--------------------------------
Total 2 savedsearch found
--------------------------------

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   
search        kevin         Test_Savedsearch2   savedsearch   user          None          None          False         
search        kevin         Test_Savedsearch3   savedsearch   app           *             admin         False         

Do you want to change now?[y/n] y

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        Status    
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   ========  
search        kevin         Test_Savedsearch2   savedsearch   user          None          None          False         Changed   
search        kevin         Test_Savedsearch3   savedsearch   app           *             admin         False         Changed  
[splunk@splunkserver01 ~]$
```

#### To change owner, sharing permission and read & write permission of selected knowledge object owned by any user
In below example we will change selected savedsearch owned by any user to "kevin" user, change sharing permission from `user` to `app` level and change read to everyone and write permission to `power` and `user` roles in all splunk apps. I have created `savedsearch.txt` file and mentioned `Test_Savedsearch2` as given below.

```
[splunk@splunkserver01 ~]$ cat /home/splunk/savedsearch.txt
Test_Savedsearch2
[splunk@splunkserver01 ~]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py change savedsearch --file /home/splunk/savedsearch.txt --newuser kevin --readperm '*' --writeperm power,user --sharing app
Authentication method:
1.) Username and Password
2.) Auth token
Please select authentication method (Enter 1 or 2): 1
Enter username with admin privileges: admin
Enter password:
Fetched 30 out of total 85 knowledge objects.
Fetched 60 out of total 85 knowledge objects.
Fetched 85 out of total 85 knowledge objects.

--------------------------------
Total 1 savedsearch found
--------------------------------

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   
search        bob           Test_Savedsearch2   savedsearch   user          None          None          False         

Do you want to change now?[y/n] y

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        Status    
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   ========  
search        bob           Test_Savedsearch2   savedsearch   user          None          None          False         Changed  
[splunk@splunkserver01 ~]$
[splunk@splunkserver01 ~]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py list savedsearch --file /home/splunk/savedsearch.txt
Authentication method:
1.) Username and Password
2.) Auth token
Please select authentication method (Enter 1 or 2): 1
Enter username with admin privileges: admin
Enter password:
Fetched 30 out of total 85 knowledge objects.
Fetched 60 out of total 85 knowledge objects.
Fetched 85 out of total 85 knowledge objects.

--------------------------------
Total 1 savedsearch found
--------------------------------

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   
search        kevin         Test_Savedsearch2   savedsearch   app           *             power,user    False         

[splunk@splunkserver01 ~]$
```

#### To move knowledge object owned by user from one app to another app
In below example we will move savedsearch owned by "bob" user from all splunk apps to "test_app" app.

```
[splunk@splunkserver01 etc]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py move savedsearch --user bob --newapp test_app
Authentication method:
1.) Username and Password
2.) Auth token
Please select authentication method (Enter 1 or 2): 1
Enter username with admin privileges: admin
Enter password:
Fetched 1 out of total 1 knowledge objects.

--------------------------------
Total 1 savedsearch found
--------------------------------

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   
search        bob           Test_Savedsearch3   savedsearch   app           *             admin         False         

Do you want to move now?[y/n] y

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        Status    
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   ========  
search        bob           Test_Savedsearch3   savedsearch   app           *             admin         False         Moved    
[splunk@splunkserver01 etc]$
```

#### To move selected knowledge objects owned by any user from one app to another app
In below example we will move savedsearch owned by any user from all splunk apps to "test_app" app. I have created `savedsearch.txt` file and mentioned `Test_Savedsearch2` as given below.

```
[splunk@splunkserver01 etc]$ cat /home/splunk/savedsearch.txt
Test_Savedsearch2
[splunk@splunkserver01 etc]$ /opt/splunk/bin/splunk cmd python /home/splunk/ko_change.py move savedsearch --file /home/splunk/savedsearch.txt --newapp test_app
Authentication method:
1.) Username and Password
2.) Auth token
Please select authentication method (Enter 1 or 2): 1
Enter username with admin privileges: admin
Enter password:
Fetched 30 out of total 85 knowledge objects.
Fetched 60 out of total 85 knowledge objects.
Fetched 85 out of total 85 knowledge objects.

--------------------------------
Total 1 savedsearch found
--------------------------------

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   
search        kevin         Test_Savedsearch2   savedsearch   app           *             power,user    False         

Do you want to move now?[y/n] y

App Name      Author Name   Title               Type of KO    Sharing       Read Perm     Write Perm    Orphan        Status    
===========   ===========   ===========         ===========   ===========   ===========   ===========   ===========   ========  
search        kevin         Test_Savedsearch2   savedsearch   app           *             power,user    False         Moved    
[splunk@splunkserver01 etc]$
```
