import re
import tkinter as tk
from tkinter import ttk, messagebox
import pandas as pd
import spider


class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("poc管理")
        self.geometry("800x600")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.columns = ("cve_id", "product_name", "has_exp", "published_date", "vul_type", "description")
        self.reverseFlag = False
        #search_var搜索到的结果 option_var搜索的关键词
        self.option_var = 'pikachu'
        self.search_var = 'pikachu'

        self.data = pd.DataFrame({'status': 10000, 'message': 'success', 'data': {}})
        self.page_size = 50
        self.current_page = 0
        self.total_pages = (len(self.data) - 1) // self.page_size + 1
        self.total = 10



        # 搜索框
        search_frame = tk.Frame(self)

        search_frame.grid(row=0, column=0, sticky="nsew")
        search_frame.columnconfigure(0, weight=1)
        # 下拉框
        #option_var = tk.StringVar()
        # option_var.set("请选择数据来源")

        self.option_menu = ttk.Combobox(search_frame, values=["奇安信", "360", "斗象"],state="readonly")
        # 绑定"<<ComboboxSelected>>"事件
        self.option_menu.current(0)
        self.option_menu.bind("<<ComboboxSelected>>", self.on_combobox_selected)
        self.option_menu.grid(row=0, column=1, padx=10, pady=10)

        #搜索框
        self.textVar = tk.StringVar()
        self.textVar.set('在这里输入想要搜索的漏洞/组件关键字...')
        self.search_entry = ttk.Entry(search_frame,  width=30, font=('Arial', 10), textvariable=self.textVar)
        self.search_entry.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.search_entry.bind('<KeyRelease>', self.on_search_entry_key_release)

        # 搜索结果展示区域
        self.result_text = tk.Text(self, height=10, width=50)
        self.result_text.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

        #确认按钮
        search_button = ttk.Button(search_frame, text="搜索", command=self.search_button_confirm)

        search_button.grid(row=0, column=2, sticky="nsew", padx=10, pady=10)

        # 表格
        table_frame = tk.Frame(self)
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self.table = ttk.Treeview(table_frame, columns=self.columns, show="headings")
        #table.column("col1", width=200, anchor="w")
        #table.column("col2", width=200, anchor="w")
        #table.column("col3", width=200, anchor="w")
        for i, header in enumerate(self.columns):
            self.table.heading(i, text=header, command=lambda c=header: self.treeview_sortColumn(c))


        self.table.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.table.bind('<Button-3>', self.RightClicked)
        # 竖直滚动条
        vsb = tk.Scrollbar(self, orient='vertical', command=self.table.yview)
        hsb = ttk.Scrollbar(self, orient='horizontal', command=self.table.xview)
        self.table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.grid(column=3, row=1, sticky='ns')
        hsb.grid(column=0, row=2, sticky='ew')

        #翻页按钮

        button_frame = tk.Frame(self)
        button_frame.grid(row=3, column=0)
        button_frame.columnconfigure(0, weight=1)
        button_frame.rowconfigure(0, weight=1)
        prev_button = ttk.Button(button_frame, text="上一页", command=self.prev_page)
        next_button = ttk.Button(button_frame, text="下一页", command=self.next_page)

        self.page_label = tk.Label(button_frame, text='')

        home_button = ttk.Button(button_frame, text="首页", command=self.home_button_confirm)
        end_button = ttk.Button(button_frame, text="尾页", command=self.end_button_confirm)
        prev_button.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        next_button.grid(row=0, column=3, sticky="nsew", padx=10, pady=10)

        self.page_label.grid(row=0, column=2, sticky="nsew", padx=10, pady=10)

        home_button.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        end_button.grid(row=0, column=4, sticky="nsew", padx=10, pady=10)

        self.init_table()

        #self.update_table()

    #右键事件 弹出菜单
    def RightClicked(self, event):
        print(1234)

        # 创建一个菜单
        popup_menu = tk.Menu(self.table, tearoff=False)
        popup_menu.add_command(label="搜索poc",command=self.Tree_Focus_Area)
        popup_menu.add_command(label="搜索exp",command=self.callback1)
        popup_menu.add_command(label="在线验证",command=self.callback1)
        # 显示菜单
        popup_menu.post(event.x_root, event.y_root)

    def callback1(self):
        messagebox.showinfo("Message", "功能暂未开发完成，敬请期待！")

    def copy(self, listbox):
        listbox.event_generate("<<Copy>>")
    def createNewWindow(self, poclist):

        newWindow = tk.Toplevel(app)
        newWindow.geometry("400x300")
        #labelExample = tk.Label(newWindow, text="POC List")
        #buttonExample = tk.Button(newWindow, text="New Window button")
        listbox = tk.Listbox(newWindow,width=400,height=300)

        for item in poclist:
            listbox.insert("end", item)
        listbox.grid(row=0, column=0, sticky="nsew")
        #labelExample.pack()
        #buttonExample.pack()
    def Tree_Focus_Area(self):

        selections = self.table.selection()
        rows = [self.table.item(i, 'values') for i in selections]
        for i, row in enumerate(rows, 1):
            has_poc = re.search('False', str(row))
            if has_poc:
                messagebox.showinfo("Message", "该cve暂未爆出公开poc！")
                return 0
            cve = re.search('CVE-[\d]*-[\d]*', str(row))
            if cve:
                print(f"The selected items for ID #{i}:", cve.group())
                poc_list = spider.search_github_poc(cve.group())
                self.createNewWindow(poc_list)
            else:
                 messagebox.showinfo("Message", "不存在CVE编号，暂不支持查询！")

    def init_table(self):
        print(self.total_pages)
        print(self.current_page)
        start = self.current_page * self.page_size
        end = min(start + self.page_size, len(self.data))
        page_data = self.data.iloc[start:end]
        self.table.delete(*self.table.get_children())

        for i, row in page_data.iterrows():
            self.table.insert('', 'end', iid=i, values=list(row))

        #self.total_pages = (len(self.data) - 1) // self.page_size + 1
        self.page_label.config(text=f'Page {self.current_page} of {self.total_pages}')

    def update_table(self, keyword, release):

        #total = spider.qianxin(keyword=keyword)

        if release == "奇安信":
            total = spider.qianxin(keyword=keyword)
            self.data = spider.qianxin(keyword, 1, total_data=total)[0]
            self.total = spider.qianxin(keyword, 1, total_data=total)[1]
            self.data_tmp = pd.DataFrame(self.data)
        if release == "斗象":

            messagebox.showinfo("Message", "暂未适配此数据源，该功能敬请期待！")

            #total_dou = spider.douxiang(keyword=keyword)

            #self.data = spider.douxiang(keyword, 1, total_data=total_dou)[0]

            #self.total = spider.douxiang(keyword, 1, total_data=total_dou)[1]

            #self.data_tmp = pd.DataFrame(self.data)
        if release == "360":
            messagebox.showinfo("Message", "暂未适配此数据源，该功能敬请期待！")


        for i in range(0, self.total):
            # data = spider.qianxin('1234', i, total_data=len1)
            self.table.insert("", "end", values=(self.data[i][0], self.data[i][1], self.data[i][2], self.data[i][3], self.data[i][4], self.data[i][5]))

        start = self.current_page * self.page_size
        end = min(start + self.page_size, len(self.data))
        page_data = self.data_tmp.iloc[start:end]
        self.table.delete(*self.table.get_children())

        for i, row in page_data.iterrows():
            self.table.insert('', 'end', iid=i, values=list(row))

        self.total_pages = (len(self.data) - 1) // self.page_size + 1
        #默认从第一页开始技术
        self.page_label.config(text=f'Page {1} of {self.total_pages}')


    def update_page(self):

        start = self.current_page * self.page_size
        end = min(start + self.page_size, len(self.data))
        page_data = self.data_tmp.iloc[start:end]
        self.table.delete(*self.table.get_children())

        for i, row in page_data.iterrows():
            self.table.insert('', 'end', iid=i, values=list(row))

        self.total_pages = (len(self.data) - 1) // self.page_size + 1
        self.page_label.config(text=f'Page {self.current_page + 1} of {self.total_pages}')

    def end_button_confirm(self):
        if self.current_page != self.total_pages-1:
            self.current_page = self.total_pages-1
            self.update_page()

    def home_button_confirm(self):
        if self.current_page != 0:
            self.current_page = 0
            self.update_page()


    def next_page(self):
        if self.current_page < self.total_pages - 1:
            self.current_page += 1
            self.update_page()

    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.update_page()
    def treeview_sortColumn(self, col):
        #global reverseFlag  # 定义排序标识全局变量
        lst = [(self.table.set(st, col), st)
               for st in self.table.get_children("")]
        print(lst)  # 打印列表
        lst.sort(reverse=self.reverseFlag)  # 排序列表
        print(lst)  # 打印列表
        for index, item in enumerate(lst):  # 重新移动项目内容
            self.table.move(item[1], "", index)
        self.reverseFlag = not self.reverseFlag  # 更改排序标识

    #搜索按钮点击事件监控
    def search_button_confirm(self):

        keyword = self.on_search_entry_key_release(self)
        release = self.on_combobox_selected(self)

        messagebox.showinfo("Message", "Release: {}, Search: {}".format(release, keyword))
        self.update_table(keyword=keyword, release=release)


    def on_search_entry_key_release(self, event):
        search_text = self.search_entry.get()
        print(search_text)
        return search_text

    def on_combobox_selected(self, event):
        # 获取选中的值
        value = self.option_menu.get()
        print(value)
        return value


'''
todo:
    1.右键导出结果，保存到本地csv （？？好像不是很需要这个功能）
    2.链接数据库sqlite，第一次爬取后保存到本地数据库，后面再次查询就很方便（但要提供定时更新数据库功能
    3.将各个源的数据整合到一起（去重 保存
    4.可以双击/右键查看对应漏洞编号的exp 如：双击后弹出exp地址
    5.排序 目前是只根据每页进行了排序。。
    
    资产发现->指纹识别->漏洞检测/验证->（如存在漏洞）漏洞利用
    
    本工具服务第三步漏洞检测/验证：
    期望可以开发完成为一个接口，可以通过接口调用，查询各数据源某组件（如gitlab）历史漏洞信息，并返回存在exp的高危漏洞
    批量检测组件，搜索历史漏洞，给出对应exp/poc
'''

app = App()
app.mainloop()

