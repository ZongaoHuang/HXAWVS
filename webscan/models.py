from django.db import models
from django.utils.html import format_html
from django.contrib.auth.models import User
from django.utils import timezone
import pytz

class Category(models.Model):
    """安全导航条目分类"""
    name = models.CharField(max_length=20, verbose_name='名称')
    sort = models.IntegerField(default=1, verbose_name='显示顺序')
    add_menu = models.BooleanField(default=True, verbose_name='添加到导航栏')
    icon = models.CharField(max_length=30, default='fas fa-home',verbose_name='图标')
    class Meta:
        verbose_name_plural=verbose_name = '分类'
    #统计分类对应条目数,并放入后台
    def get_items(self):
        return len(self.item_set.all())
    get_items.short_description = '条目数'  # 设置后台显示表头
    #后台图标预览
    def icon_data(self):#引入Font Awesome Free 5.11.1
        return format_html('<h1><i class="{}"></i></h1>',self.icon) #转化为<i class="{self.icon}"></i>
    icon_data.short_description = '图标预览'
    def __str__(self):
        return self.name

class Item(models.Model):
    '''安全导航条目'''
    title = models.CharField(max_length=50,verbose_name='名称')
    desc = models.TextField(max_length=100,verbose_name='描述')
    url = models.URLField(verbose_name='网址',blank=True)
    img = models.URLField(default='https://jwt1399.top/favicon.png',verbose_name='logo')
    img_width = models.IntegerField(default=45, verbose_name='图片宽度')
    category = models.ForeignKey(Category, blank=True, null=True, verbose_name='分类', on_delete=models.CASCADE)
    class Meta:
        verbose_name=verbose_name_plural='导航条目'
    #后台条目图片预览
    def img_admin(self):
        return format_html( '<img src="{}" width="50px" height="50px" style="border-radius: 50%;" />',self.img,)
    img_admin.short_description = 'logo预览'
    def __str__(self):
        return self.title

class FpCategory(models.Model):
    """指纹条目分类"""
    name = models.CharField(max_length=20, verbose_name='名称')
    class Meta:
        verbose_name_plural=verbose_name = '分类'
    #统计分类对应条目数,并放入后台
    def get_items(self):
        return len(self.fingerprint_set.all())
    get_items.short_description = '指纹数'  # 设置后台显示表头
    def __str__(self):
        return self.name

class FingerPrint(models.Model):
    '''指纹条目'''
    name = models.CharField(max_length=200, verbose_name='组件名称')
    desc = models.CharField(max_length=200, verbose_name='组件描述')
    icon = models.FileField(upload_to='icons/', verbose_name='组件logo',default="/icons/default.ico",max_length=100)
    category = models.ForeignKey(FpCategory, blank=True, null=True, verbose_name='组件类别', on_delete=models.CASCADE)
    class Meta:
        verbose_name=verbose_name_plural='指纹组件'
    def icon_data(self):
        return format_html(
            '<img src="/media/{}" width="50px" height="50px" />',
            self.icon,
        )
    icon_data.short_description = 'logo'


class PortList(models.Model):
    '''端口列表'''
    num = models.BigIntegerField(verbose_name='端口号')
    service = models.TextField(max_length=100,verbose_name='服务')
    protocol = models.CharField(max_length=20,verbose_name='协议',blank=True,default='未知')
    status = models.CharField(max_length=10,verbose_name='状态',blank=True,default='未知')
    class Meta:
        verbose_name=verbose_name_plural='端口列表'
        
class Log(models.Model):
    '''操作日志'''
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='用户')
    action = models.CharField(max_length=200, verbose_name='操作')
    action_time = models.DateTimeField(auto_now_add=True, verbose_name='操作时间')

    class Meta:
        verbose_name = '操作日志'
        verbose_name_plural = '操作日志'
        ordering = ['-action_time']

    def __str__(self):
        return f"{self.user} - {self.action} - {self.action_time}"

    def formatted_action_time(self):
        shanghai_tz = pytz.timezone('Asia/Shanghai')
        shanghai_time = self.action_time.astimezone(shanghai_tz)
        return shanghai_time.strftime("%Y-%m-%d %H:%M:%S")
    formatted_action_time.short_description = '操作时间'
    
    
    
class VulnList(models.Model):
    '''漏洞列表'''
    # ID = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='ID')
    vuln_name = models.CharField(max_length=200, verbose_name='漏洞名称')
    vuln_details = models.CharField(max_length=200,verbose_name='漏洞描述',blank=True,default='未知')
    vuln_type = models.CharField(max_length=200, verbose_name='漏洞分类', blank=True, default='未知')
    class Meta:
        verbose_name = '漏洞列表'
        verbose_name_plural = '漏洞列表'