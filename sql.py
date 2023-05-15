import sqlite3

# 连接数据库（如果不存在则创建）
conn = sqlite3.connect('example.db')

#创建游标
cursor = conn.cursor()

#创建CVE表
cursor.execute('''CREATE TABLE cve
       (ID INT PRIMARY KEY     NOT NULL,
       CVE_ID           TEXT    NOT NULL,
       PRODUCT          TEXT    NOT NULL,
       HAS_POC          INTEGER CHECK (HAS_POC IN (0, 1)) NOT NULL,
       HAS_EXP          INTEGER CHECK (HAS_EXP IN (0, 1)) NOT NULL,
       HAS_patch        TEST,
       PUBLISHED_DATE   DATETIME NOT NULL,
       DESCRIPTION      TEXT    );''')


#创建poc表
cursor.execute('''CREATE TABLE poc
       (ID INT PRIMARY KEY     NOT NULL,
       CVE_ID           TEXT    NOT NULL,
       POC_ref          TEXT    NOT NULL,
       PRODUCT          TEXT,
       PUBLISHED_DATE   DATETIME,
       DESCRIPTION      TEXT,
       FOREIGN KEY (CVE_ID) REFERENCES cve(CVE_ID));''')

#创建exp表

cursor.execute('''CREATE TABLE exp
       (ID INT PRIMARY KEY     NOT NULL,
       CVE_ID           TEXT    NOT NULL,
       EXP_ref          TEXT    NOT NULL,
       PRODUCT          TEXT,
       PUBLISHED_DATE   DATETIME,
       DESCRIPTION      TEXT,
       FOREIGN KEY (CVE_ID) REFERENCES cve(CVE_ID));''')

#创建xxx

# 提交更改
conn.commit()

# 查询数据



# 关闭连接
conn.close()
